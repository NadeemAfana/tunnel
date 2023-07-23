package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

const maxLineLength = 4096 // assumed <= bufio.defaultBufSize

var ErrLineTooLong = errors.New("header line too long")

// NewChunkedReader returns a new chunkedReader that reads the data from r
// out of HTTP "chunked" format and returns io.EOF when the final 0-length chunk is Read.
func NewChunkedReader(r io.Reader) io.Reader {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	return &chunkedReader{r: br}
}

type chunkedReader struct {
	r                  *bufio.Reader
	unreadBytesInChunk uint64 // Unread bytes in chunk
	err                error
	buf                [2]byte
	checkEnd           bool // Whether need to check for \r\n chunk footer
	outputSlice        []uint8
	// How many bytes written into outputSlice from chunk body (ie not headers or footers)
	outputBytesFromBody     int
	outputTotalBytesWritten int
	line                    []byte

	// Bytes Read into buffer (buf or line) but not yet written into outputSlice
	unwrittenBytesInBuffer int
}

func (cp *chunkedReader) beginChunk() {
	// chunk-size CRLF
	var line []byte
	line, cp.err = cp.readChunkLine(cp.r)
	if cp.err != nil {
		return
	}
	cp.unreadBytesInChunk, cp.err = parseHexUint(line)
	if cp.err != nil {
		return
	}

}

func (cp *chunkedReader) chunkHeaderAvailable() bool {
	bufferedCount := cp.r.Buffered()
	if bufferedCount > 0 {
		peek, _ := cp.r.Peek(bufferedCount)
		return bytes.IndexByte(peek, '\n') >= 0
	}
	return false
}

func (cp *chunkedReader) Read(output []uint8) (n int, err error) {
	cp.outputSlice = output
	cp.outputTotalBytesWritten = 0
	cp.outputBytesFromBody = 0
	for cp.err == nil {
		if cp.checkEnd {
			if cp.outputBytesFromBody > 0 && cp.r.Buffered() < 2 && cp.unwrittenBytesInBuffer == 0 {
				// We have some data. Return early (per the io.Reader
				// contract) instead of potentially blocking while
				// reading more.
				break
			}
			// Read the next 2 bytes if we did not already
			if cp.unwrittenBytesInBuffer == 0 {
				if cp.unwrittenBytesInBuffer, cp.err = io.ReadFull(cp.r, cp.buf[:2]); cp.err == nil {
					if string(cp.buf[:]) != "\r\n" {
						cp.err = errors.New("malformed chunked encoding")
						break
					}
				} else {
					if cp.err == io.EOF {
						cp.err = io.ErrUnexpectedEOF
					}
					break
				}
			}
			// Succeeded
			// Write buffered footer to outputSlice
			if len(cp.outputSlice) == 0 {
				// Not enough space to write, return
				break
			}
			cp.flushFooter()

			if cp.unreadBytesInChunk == 0 && cp.unwrittenBytesInBuffer == 0 && string(cp.line[:]) == "0\r\n" {
				// Added from beginChunk after  Read line
				cp.err = io.EOF
				continue
			}
		}

		// Write pending line into outputSlice if any
		if cp.unwrittenBytesInBuffer > 0 {

			if len(cp.outputSlice) == 0 {
				// Not enough space to write, return
				break
			}

			// Pending line to write
			cp.flushLine()

			if cp.unwrittenBytesInBuffer != 0 {
				break
			}

			if cp.unreadBytesInChunk == 0 {
				// Added from beginChunk after  Read line
				// Read the footer and return
				//cp.checkEnd = true
				if string(cp.line[:]) == "0\r\n" {
					// Write the final \r\n of the body
					cp.checkEnd = true
					continue
				}
				cp.err = io.EOF
				continue
			}
		}
		if cp.unreadBytesInChunk == 0 {
			if cp.outputBytesFromBody > 0 && !cp.chunkHeaderAvailable() {
				// We've Read enough. Don't potentially block
				// reading a new chunk header.
				break
			}
			cp.beginChunk()
			continue
		}
		if len(cp.outputSlice) == 0 {
			break
		}

		tmpSlice := cp.outputSlice

		// Shrink tmpSlice size if it's larger than chunk size
		if uint64(len(tmpSlice)) > cp.unreadBytesInChunk {
			tmpSlice = tmpSlice[:cp.unreadBytesInChunk]
		}
		var n0 int
		n0, cp.err = cp.r.Read(tmpSlice)
		cp.outputSlice = cp.outputSlice[n0:]
		cp.outputTotalBytesWritten += n0
		cp.outputBytesFromBody += n0
		cp.unreadBytesInChunk -= uint64(n0)
		// If we're at the end of a chunk, Read the next two
		// bytes to verify they are "\r\n".
		if cp.unreadBytesInChunk == 0 && cp.err == nil {
			cp.checkEnd = true
		} else if cp.err == io.EOF {
			cp.err = io.ErrUnexpectedEOF
		}
	}
	return cp.outputTotalBytesWritten, cp.err
}

// Read a line of bytes (up to \n) from b into output.
// Give up if the line exceeds maxLineLength.
// The returned bytes are owned by the bufio.Reader
// so they are only valid until the next bufio Read.
func (cp *chunkedReader) readChunkLine(b *bufio.Reader) ([]byte, error) {
	var err error
	cp.line, err = b.ReadSlice('\n')
	cp.unwrittenBytesInBuffer = len(cp.line)
	if err != nil {
		// We always know when EOF is coming.
		// If the caller asked for a line, there should be a line.
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		} else if err == bufio.ErrBufferFull {
			err = ErrLineTooLong
		}
		return nil, err
	}
	if len(cp.line) >= maxLineLength {
		return nil, ErrLineTooLong
	}

	p := trimTrailingWhitespace(cp.line)
	p, err = removeChunkExtension(p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// flushFooter flushes the buffered footer `buf` into `outputSlice`
func (cp *chunkedReader) flushFooter() {
	rbuf := cp.outputSlice
	if len(rbuf) > cp.unwrittenBytesInBuffer {
		rbuf = rbuf[:cp.unwrittenBytesInBuffer]
	}
	n0 := copy(rbuf, cp.buf[len(cp.buf)-cp.unwrittenBytesInBuffer:])
	cp.outputTotalBytesWritten += n0
	cp.outputSlice = cp.outputSlice[n0:]
	cp.unwrittenBytesInBuffer -= n0

	if cp.unwrittenBytesInBuffer == 0 {
		// Mark end as checked
		cp.checkEnd = false
	}

}

// flushLine flushes the buffered line into `outputSlice`
func (cp *chunkedReader) flushLine() {
	rbuf := cp.outputSlice
	if len(rbuf) > cp.unwrittenBytesInBuffer {
		rbuf = rbuf[:cp.unwrittenBytesInBuffer]
	}
	n0 := copy(rbuf, cp.line[len(cp.line)-cp.unwrittenBytesInBuffer:])
	cp.outputTotalBytesWritten += n0
	cp.outputSlice = cp.outputSlice[n0:]
	cp.unwrittenBytesInBuffer -= n0
}

func trimTrailingWhitespace(b []byte) []byte {
	for len(b) > 0 && isASCIISpace(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	return b
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

var semi = []byte(";")

// removeChunkExtension removes any chunk-extension from p.
// For example,
//
//	"0" => "0"
//	"0;token" => "0"
//	"0;token=val" => "0"
//	`0;token="quoted string"` => "0"
func removeChunkExtension(p []byte) ([]byte, error) {
	p, _, _ = bytes.Cut(p, semi)
	// TODO: care about exact syntax of chunk extensions? We're
	// ignoring and stripping them anyway. For now just never
	// return an error.
	return p, nil
}

func parseHexUint(v []byte) (n uint64, err error) {
	for i, b := range v {
		switch {
		case '0' <= b && b <= '9':
			b = b - '0'
		case 'a' <= b && b <= 'f':
			b = b - 'a' + 10
		case 'A' <= b && b <= 'F':
			b = b - 'A' + 10
		default:
			return 0, errors.New("invalid byte in chunk length")
		}
		if i == 16 {
			return 0, errors.New("http chunk length too large")
		}
		n <<= 4
		n |= uint64(b)
	}
	return
}
