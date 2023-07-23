package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http/httputil"
	"strings"
	"testing"
	"testing/iotest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Chunk Reader", func() {
	It("should Read a chunk", func() {
		var b bytes.Buffer

		w := httputil.NewChunkedWriter(&b)
		const chunk1 = "hello, "
		const chunk2 = "world! 0123456789abcdef"
		w.Write([]byte(chunk1))
		w.Write([]byte(chunk2))
		w.Close()
		b.WriteString("\r\n")

		if g, e := b.String(), "7\r\nhello, \r\n17\r\nworld! 0123456789abcdef\r\n0\r\n\r\n"; g != e {
			Fail(fmt.Sprintf("chunk writer wrote %q; want %q", g, e))
		}

		r := NewChunkedReader(&b)
		data, err := io.ReadAll(r)
		Expect(err).To(BeNil(), "ReadAll from processor: %v", err)

		if g, e := string(data), "7\r\nhello, \r\n17\r\nworld! 0123456789abcdef\r\n0\r\n\r\n"; g != e {
			Fail(fmt.Sprintf("chunk processor wrote %q; want %q", g, e))
		}
	})

	It("should Read chunks when buffer is smaller than chunks size", func() {
		var b bytes.Buffer
		expected := "7\r\nhello, \r\n17\r\nworld! 0123456789abcdef\r\n0\r\n\r\n"
		for i := 0; i < len(expected)-1; i++ {
			b.Reset()
			w := httputil.NewChunkedWriter(&b)
			const chunk1 = "hello, "
			const chunk2 = "world! 0123456789abcdef"
			w.Write([]byte(chunk1))
			w.Write([]byte(chunk2))
			w.Close()
			b.WriteString("\r\n")

			if g, e := b.String(), expected; g != e {
				Fail(fmt.Sprintf("chunk writer wrote %q; want %q", g, e))
			}

			r := NewChunkedReader(bufio.NewReaderSize(&b, i))
			data, err := io.ReadAll(r)
			Expect(err).To(BeNil(), "ReadAll from processor: %v", err)

			if g, e := string(data), expected; g != e {
				Fail(fmt.Sprintf("chunk processor wrote %q; want %q", g, e))
			}
		}
	})

	It("TestChunkReadMultiple", func() {
		// Bunch of small chunks, all Read together.
		{
			var b bytes.Buffer
			w := httputil.NewChunkedWriter(&b)
			w.Write([]byte("foo"))
			w.Write([]byte("bar"))
			w.Close()
			b.WriteString("\r\n")

			bLength := b.Len()

			r := NewChunkedReader(&b)
			buf := make([]byte, 21)
			n, err := r.Read(buf)
			if n != bLength || err != io.EOF {
				Fail(fmt.Sprintf("Read = %d, %v; want %d, EOF", n, err, bLength))
			}

			if string(buf) != "3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n" {
				Fail(fmt.Sprintf("Read = %q; want %q", buf, b))
			}
		}

		// One big chunk followed by a little chunk, with a small bufio.Reader size
		// should read as much as possible in the buffer
		{
			var b bytes.Buffer
			w := httputil.NewChunkedWriter(&b)
			// fillBufChunk is 11 bytes + 3 bytes header + 2 bytes footer = 16 bytes,
			// the same as the bufio ReaderSize below (the minimum), so even
			// though we're going to try to Read with a buffer larger enough to also
			// receive "foo", the second chunk header won't be Read yet.
			const fillBufChunk = "0123456789a"
			const shortChunk = "foo"
			w.Write([]byte(fillBufChunk))
			w.Write([]byte(shortChunk))
			w.Close()
			b.WriteString("\r\n")

			totalLength := b.Len()

			r := NewChunkedReader(bufio.NewReaderSize(&b, 16))
			buf := make([]byte, b.Len())
			n, err := r.Read(buf)
			// Should fill the whole buffer 16 bytes
			if n != 16 || err != nil {
				Fail(fmt.Sprintf("Read = %d, %v; want %d, nil", n, err, 16))
			}
			buf = buf[:n]
			if string(buf) != "b\r\n"+fillBufChunk+"\r\n" {
				Fail(fmt.Sprintf("Read = %q; want %q", buf, "b\r\n"+fillBufChunk+"\r\n"))
			}

			n, err = r.Read(buf)
			if n != totalLength-16 || err != io.EOF {
				Fail(fmt.Sprintf("Read = %d, %v; want %d, EOF", n, err, totalLength-len(fillBufChunk)-3))
			}
		}

		// And test that we see an EOF chunk, even though our buffer is already full:
		{
			r := NewChunkedReader(bufio.NewReader(strings.NewReader("3\r\nfoo\r\n0\r\n\r\n")))
			buf := make([]byte, 13)
			n, err := r.Read(buf)
			if n != 13 || err != io.EOF {
				Fail(fmt.Sprintf("Read = %d, %v; want 13, EOF", n, err))
			}
			if string(buf) != "3\r\nfoo\r\n0\r\n\r\n" {
				Fail(fmt.Sprintf("buf = %q; want \"3\\r\\nfoo\\r\\n0\\r\\n\\r\\n", buf))
			}
		}
	})

	It("TestChunkReaderAllocs", func() {
		if testing.Short() {
			Skip("skipping in short mode")
		}
		var buf bytes.Buffer
		w := httputil.NewChunkedWriter(&buf)
		a, b, c := []byte("aaaaaa"), []byte("bbbbbbbbbbbb"), []byte("cccccccccccccccccccccccc")
		w.Write(a)
		w.Write(b)
		w.Write(c)
		w.Close()
		buf.WriteString("\r\n")

		bufLength := buf.Len()

		readBuf := make([]byte, bufLength+1)
		byter := bytes.NewReader(buf.Bytes())
		bufr := bufio.NewReader(byter)
		mallocs := testing.AllocsPerRun(100, func() {
			byter.Seek(0, io.SeekStart)
			bufr.Reset(byter)
			r := NewChunkedReader(bufr)
			n, err := io.ReadFull(r, readBuf)
			if n != len(readBuf)-1 {
				Fail(fmt.Sprintf("Read %d bytes; want %d", n, len(readBuf)-1))
			}
			if err != io.ErrUnexpectedEOF {
				Fail(fmt.Sprintf("Read error = %v; want ErrUnexpectedEOF", err))
			}
		})
		if mallocs > 1.5 {
			Fail(fmt.Sprintf("mallocs = %v; want 1", mallocs))
		}
	})

	It("TestParseHexUint", func() {
		type testCase struct {
			in      string
			want    uint64
			wantErr string
		}
		tests := []testCase{
			{"x", 0, "invalid byte in chunk length"},
			{"0000000000000000", 0, ""},
			{"0000000000000001", 1, ""},
			{"ffffffffffffffff", 1<<64 - 1, ""},
			{"000000000000bogus", 0, "invalid byte in chunk length"},
			{"00000000000000000", 0, "http chunk length too large"}, // could accept if we wanted
			{"10000000000000000", 0, "http chunk length too large"},
			{"00000000000000001", 0, "http chunk length too large"}, // could accept if we wanted
		}
		for i := uint64(0); i <= 1234; i++ {
			tests = append(tests, testCase{in: fmt.Sprintf("%x", i), want: i})
		}
		for _, tt := range tests {
			got, err := parseHexUint([]byte(tt.in))
			if tt.wantErr != "" {
				if !strings.Contains(fmt.Sprint(err), tt.wantErr) {
					Fail(fmt.Sprintf("parseHexUint(%q) = %v, %v; want error %q", tt.in, got, err, tt.wantErr))
				}
			} else {
				if err != nil || got != tt.want {
					Fail(fmt.Sprintf("parseHexUint(%q) = %v, %v; want %v", tt.in, got, err, tt.want))
				}
			}
		}
	})

	It("TestChunkReadingIgnoresExtensions", func() {
		// We don't ignore extensions; we Read everything.
		in := "7;ext=\"some quoted string\"\r\n" + // token=quoted string
			"hello, \r\n" +
			"17;someext\r\n" + // token without value
			"world! 0123456789abcdef\r\n" +
			"0;someextension=sometoken\r\n" // token=token

		data, err := io.ReadAll(NewChunkedReader(strings.NewReader(in)))
		if err != nil {
			Fail(fmt.Sprintf("ReadAll = %q, %v", data, err))
		}
		if g, e := string(data), in; g != e {
			Fail(fmt.Sprintf("Read %q; want %q", g, e))
		}
	})

	// Issue 17355: ChunkedReader shouldn't block waiting for more data
	// if it can return something.
	It("func TestChunkReadPartial", func() {
		pr, pw := io.Pipe()
		go func() {
			pw.Write([]byte("7\r\n1234567"))
		}()
		cr := NewChunkedReader(pr)
		readBuf := make([]byte, 10)
		n, err := cr.Read(readBuf)
		if err != nil {
			Fail(fmt.Sprint(err))
		}
		want := "7\r\n1234567"
		if n != 10 || string(readBuf) != want {
			Fail(fmt.Sprintf("Read: %v %q; want %d, %q", n, readBuf[:n], len(want), want))
		}
		go func() {
			pw.Write([]byte("xx"))
		}()
		_, err = cr.Read(readBuf)
		if got := fmt.Sprint(err); !strings.Contains(got, "malformed") {
			Fail(fmt.Sprintf("second Read = %v; want malformed error", err))
		}
	})

	// Issue 48861: ChunkedReader should report incomplete chunks
	It("func TestIncompleteChunk", func() {
		const valid = "4\r\nabcd\r\n" + "5\r\nabc\r\n\r\n" + "0\r\n\r\n"

		for i := 0; i < len(valid); i++ {
			incomplete := valid[:i]
			r := NewChunkedReader(strings.NewReader(incomplete))
			if _, err := io.ReadAll(r); err != io.ErrUnexpectedEOF {
				Fail(fmt.Sprintf("expected io.ErrUnexpectedEOF for %q, got %v", incomplete, err))
			}
		}

		r := NewChunkedReader(strings.NewReader(valid))
		if _, err := io.ReadAll(r); err != nil {
			Fail(fmt.Sprintf("unexpected error for %q: %v", valid, err))
		}
	})

	It("func TestChunkEndReadError", func() {
		readErr := fmt.Errorf("chunk end Read error")

		r := NewChunkedReader(io.MultiReader(strings.NewReader("4\r\nabcd"), iotest.ErrReader(readErr)))
		if _, err := io.ReadAll(r); err != readErr {
			Fail(fmt.Sprintf("expected %v, got %v", readErr, err))
		}
	})

})
