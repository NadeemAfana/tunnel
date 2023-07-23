package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http/httpguts"
)

var zeroLengthChunk = []byte("0\r\n\r\n")

type httpProcessor struct {
	buf                     []byte
	reader                  io.Reader
	bufReadPos, bufWritePos int   // Buffer Read/write positions
	totalBytes              int64 // Total bytes Read so far
	bufferUsed              bool  // true if the buffer has been completed Read from
	parsedHeaders           bool
	lastError               error
	headers                 map[string][]string
	URL                     *url.URL
	bodyStartsIndex         int
	bodyLength              int64
	headerBodyReader        io.Reader
}

func newHttpProcessor(rd io.Reader, buffer []byte) *httpProcessor {
	if b, ok := rd.(*httpProcessor); ok {
		return b
	}
	p := new(httpProcessor)
	p.reader = rd
	p.buf = buffer
	return p
}

// BytesRead returns Number of bytes Read so far
func (h *httpProcessor) BytesRead() int64 {
	return h.totalBytes
}
func (h *httpProcessor) GetHeaders() (map[string][]string, error) {
	err := h.ReadHeadersIfNeeded()
	return h.headers, err
}

// IsRequestChunked returns true if request is chunked; it assumes we already Read the headers
func (h *httpProcessor) IsRequestChunked() bool {
	if l, ok := h.headers["Transfer-Encoding"]; ok && len(l) > 0 {
		if l[0] == "chunked" {
			return true
		}
	}
	return false
}

func (h *httpProcessor) Close() {
	h.lastError = io.ErrUnexpectedEOF
}

func (h *httpProcessor) GetHost() (string, error) {
	err := h.ReadHeadersIfNeeded()
	if err != nil {
		return "", err
	}

	// TODO: Add unit test
	// See if the host is in the url
	if h.URL != nil {
		host := h.URL.Query().Get("host")
		if host != "" {
			return host, nil
		}
	}
	// Fallback to headers
	if header, ok := h.headers["Host"]; ok && len(header) == 1 {
		return header[0], nil
	}

	return "", errors.New("could not find Host header")
}

// Read reads data into p replacing the header if found.
// It returns the number of bytes written into p.
// It is important to only call reader.Read at most once since this can cause blocking.
func (h *httpProcessor) Read(p []byte) (n int, err error) {

	if h.lastError != nil {
		return 0, h.lastError
	}

	// Read and parse headers first.
	// Look for the first \r\n\r\n instance
	if !h.bufferUsed {
		if !h.parsedHeaders && h.bufReadPos == h.bufWritePos {
			h.bufReadPos = 0
			h.bufWritePos = 0

			n, err := h.reader.Read(h.buf)
			if err != nil {
				h.lastError = err
				return n, h.lastError
			}
			h.totalBytes += int64(n)

			h.bufWritePos += n
		}

		if !h.parsedHeaders {
			// Find headers delimiter
			// Give up if it's not in the buffer.
			firstLineEndPos := bytes.Index(h.buf, []byte("\r\n"))
			if firstLineEndPos < 0 {
				h.lastError = errors.New("could not find the  http status line within the allocated buffer")
				return 0, h.lastError
			}
			delimiter := []byte("\r\n\r\n")
			delimiterIndex := bytes.Index(h.buf, delimiter)
			if delimiterIndex > 0 {
				h.bodyStartsIndex = delimiterIndex + 4
				reader := bufio.NewReader(bytes.NewReader(h.buf[firstLineEndPos+2 : delimiterIndex+4]))
				tp := textproto.NewReader(reader)

				mimeHeader, err := tp.ReadMIMEHeader()
				if err != nil {
					h.lastError = err
					return 0, err
				}

				// Assume this is a request, not response to get the URL.
				if method, requestURI, _, ok := h.parseRequestLine(string(h.buf[0:firstLineEndPos])); ok {
					if h.validMethod(method) {
						// This is a request at this point
						if u, err := url.ParseRequestURI(requestURI); err == nil {
							h.URL = u
						}
					}
				}

				h.headers = mimeHeader
				h.parsedHeaders = true

				// headers end here
				// Wrap HTTP request with a reader that limits the size of data Read from the body
				h.GetContentLength()
				h.adjustBodyReader()

			} else {
				h.lastError = errors.New("could not Read the headers within the allocated buffer")
				return 0, h.lastError
			}
		}

		if len(p) == 0 {
			return 0, nil
		}

		// Copy as much as possible to fill p.
		// Copy from buffer into p.
		n = copy(p, h.buf[h.bufReadPos:h.bufWritePos])
		h.bufReadPos += n
		if h.bufReadPos == h.bufWritePos {
			// bufferUsed means buffer has been written completely, and it is no longer needed.
			h.bufferUsed = true
		}

		return n, h.lastError
	}

	n, err = h.reader.Read(p)
	if err != nil {
		h.lastError = err
	}
	h.totalBytes += int64(n)
	return n, h.lastError
}

// parseRequestLine parses "GET /foo HTTP/1.1" into its three parts.
func (h *httpProcessor) parseRequestLine(line string) (method, requestURI, proto string, ok bool) {
	method, rest, ok1 := cut(line, " ")
	requestURI, proto, ok2 := cut(rest, " ")
	if !ok1 || !ok2 {
		return "", "", "", false
	}
	return method, requestURI, proto, true
}

// Upgrade to latest Go and use strings.Cut instead
func cut(s, sep string) (before, after string, found bool) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

func (h *httpProcessor) validMethod(method string) bool {
	/*
	     Method         = "OPTIONS"                ; Section 9.2
	                    | "GET"                    ; Section 9.3
	                    | "HEAD"                   ; Section 9.4
	                    | "POST"                   ; Section 9.5
	                    | "PUT"                    ; Section 9.6
	                    | "DELETE"                 ; Section 9.7
	                    | "TRACE"                  ; Section 9.8
	                    | "CONNECT"                ; Section 9.9
	                    | extension-method
	   extension-method = token
	     token          = 1*<any CHAR except CTLs or separators>
	*/
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}
func isNotToken(r rune) bool {
	return !httpguts.IsTokenRune(r)
}

func (h *httpProcessor) replaceHeader(headerName string, headerValue string) {
	h.ReadHeadersIfNeeded()
	if h.headers != nil {
		if oldHeader, ok := h.headers[headerName]; ok && len(oldHeader) == 1 {
			h.headers[headerName] = []string{headerValue}

			// Update internal buffer if it has not been used
			if !h.bufferUsed {
				start := bytes.Index(h.buf, []byte(headerName))
				if start < 0 {
					return
				}
				end := bytes.Index(h.buf[start:], []byte("\n"))
				if end < 0 {
					return
				}
				end += start
				temp := h.buf[start:end] // Host: a.b.c
				tempFixed := bytes.Replace(temp, []byte(oldHeader[0]), []byte(headerValue), 1)
				h.buf = bytes.Replace(h.buf, temp, tempFixed, 1)
				headerDiff := len(headerValue) - len(oldHeader[0])
				h.bufWritePos += headerDiff
				h.bodyStartsIndex += headerDiff
				h.adjustBodyReader()
			}
		}
	}
}

// SetHostHeader replaces host and origin headers if any
func (h *httpProcessor) SetHostHeader(header string) {
	h.ReadHeadersIfNeeded()

	h.replaceHeader("Host", header)

	// Replace origin only if its value matches the proxy domain
	if h.headers != nil {
		if oldHeader, ok := h.headers["Origin"]; ok && len(oldHeader) == 1 {
			if strings.Contains(strings.ToLower(oldHeader[0]), strings.ToLower(domain)) {
				h.replaceHeader("Origin", strings.Replace(oldHeader[0], domain, header, 1))
			}
		}
	}
}

func (h *httpProcessor) ReadHeadersIfNeeded() error {
	if !h.bufferUsed {
		// Force a buffer
		b := make([]byte, 0)
		_, err := h.Read(b)
		if err != nil {
			return err
		}
	}
	return nil
}

// TODO: Clean up and use internal variable bodyLength field

// GetContentLength returns the adjusted Content-Length:
// The parsed content length, true or
// 0, true if the request is chunked;
// Returning false requires extra un-needed logic (eg such as GET requests)
func (h *httpProcessor) GetContentLength() (int64, bool) {

	if h.IsRequestChunked() {
		return 0, true
	}

	if l, ok := h.headers["Content-Length"]; ok && len(l) > 0 {
		l, err := strconv.ParseInt(l[0], 10, 64)
		if err != nil {
			return 0, false
		}
		return l, true
	}

	// Invalid content-length
	return 0, true
}

func (h *httpProcessor) GetRequestReader() io.Reader {
	h.ReadHeadersIfNeeded()
	return h.headerBodyReader
}

// TODO: Minimize calls to this function
func (h *httpProcessor) adjustBodyReader() {

	// Look for persistent connections such as Web sockets
	upgradeConn := false
	if v, ok := h.headers["Connection"]; ok {
		if strings.ToLower(v[0]) == "upgrade" {
			upgradeConn = true
			log.Debugf("Connection is an upgrade")
		}
	}

	if upgradeConn {
		// Persist TCP connection by not limiting the body
		h.headerBodyReader = h

	} else if h.IsRequestChunked() {
		// TODO: Though acceptable behavior in terms of .Read to return partial data.
		// A single Read call on this reader is not going to return the full cached buffer data in one call, so
		// we might need to write a variant of multireader that reads the full buffer (ie only the buffer data) from limitReader and ChunkReader
		h.headerBodyReader = io.MultiReader(io.LimitReader(h, int64(h.bodyStartsIndex)), NewChunkedReader(h))
	} else {
		h.bodyLength, _ = h.GetContentLength()
		h.headerBodyReader = io.LimitReader(h, int64(h.bodyStartsIndex)+h.bodyLength)
	}
}
