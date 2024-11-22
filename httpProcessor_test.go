package main

import (
	"bytes"
	"io"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("HttpProcessor", func() {
	domainURL = "domain.io"

	It("should should read until response TCP connection closes when response is missing content-length", func() {
		// All response must be read until body reader closes
		body := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\nBody is here"
		reader := strings.NewReader(body)
		bufferSize := len(body) * 3
		buffer := make([]byte, bufferSize)
		sut := newHttpProcessor(reader, buffer)

		p := make([]byte, len(body))
		_, err := sut.GetReader().Read(p)
		Expect(string(p)).To(Equal(body))
		Expect(err).To(Not(HaveOccurred()))
	})

	It("should process response when content-length is missing for 304", func() {
		body := "HTTP/1.1 304 Not Modified\r\nContent-Type: application/json\r\n\r\n"
		reader := strings.NewReader(body)
		bufferSize := len(body) * 3
		buffer := make([]byte, bufferSize)
		sut := newHttpProcessor(reader, buffer)

		p := make([]byte, len(body))
		_, err := sut.GetReader().Read(p)
		Expect(string(p)).To(Equal(body))
		Expect(err).To(Not(HaveOccurred()))
		length, ok := sut.GetContentLength()
		Expect(length).To(BeZero())
		Expect(ok).To(BeTrue())
	})

	It("should process response when content-length is missing for 1xx", func() {
		body := "HTTP/1.1 180 Not Modified\r\nContent-Type: application/json\r\n\r\n"
		reader := strings.NewReader(body)
		bufferSize := len(body) * 3
		buffer := make([]byte, bufferSize)
		sut := newHttpProcessor(reader, buffer)

		p := make([]byte, len(body))
		_, err := sut.GetReader().Read(p)
		Expect(string(p)).To(Equal(body))
		Expect(err).To(Not(HaveOccurred()))
		length, ok := sut.GetContentLength()
		Expect(length).To(BeZero())
		Expect(ok).To(BeTrue())
	})

	It("should process response when content-length is missing for 204", func() {
		body := "HTTP/1.1 204 Not Modified\r\nContent-Type: application/json\r\n\r\n"
		reader := strings.NewReader(body)
		bufferSize := len(body) * 3
		buffer := make([]byte, bufferSize)
		sut := newHttpProcessor(reader, buffer)

		p := make([]byte, len(body))
		_, err := sut.GetReader().Read(p)
		Expect(string(p)).To(Equal(body))
		Expect(err).To(Not(HaveOccurred()))
		length, ok := sut.GetContentLength()
		Expect(length).To(BeZero())
		Expect(ok).To(BeTrue())
	})

	It("should return content length of 0 when response HTTP content-length header > 0 and request type is HEAD", func() {
		// Simulates a HEAD request response
		body := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15632\r\nHost: domain.io\nOrigin: https://domain.io:123\r\n\r\n"
		reader := strings.NewReader(body)
		bufferSize := len(body) * 3
		buffer := make([]byte, bufferSize)
		sut := newHttpProcessor(reader, buffer)
		sut.requestMethod = "HEAD"
		p := make([]byte, len(body))
		_, err := sut.GetReader().Read(p)
		length, ok := sut.GetContentLength()
		Expect(length).To(BeZero())
		Expect(ok).To(BeTrue())
		Expect(string(p)).To(Equal(body))
		Expect(err).To(Not(HaveOccurred()))
	})

	It("should return content length of 0 when response HTTP content-length header > 0 and status 2xx and request type is CONNECT", func() {
		// Simulates a CONNECT request response
		body := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15632\r\nHost: domain.io\nOrigin: https://domain.io:123\r\n\r\n"
		reader := strings.NewReader(body)
		bufferSize := len(body) * 3
		buffer := make([]byte, bufferSize)
		sut := newHttpProcessor(reader, buffer)
		sut.requestMethod = "CONNECT"
		p := make([]byte, len(body))
		_, err := sut.GetReader().Read(p)
		length, ok := sut.GetContentLength()
		Expect(length).To(BeZero())
		Expect(ok).To(BeTrue())
		Expect(string(p)).To(Equal(body))
		Expect(err).To(Not(HaveOccurred()))
	})

	It("should return correct content length when response HTTP content-length header > 0 and status not 2xx and request type is CONNECT", func() {
		// Simulates a  CONNECT request response
		body := "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 15632\r\nHost: domain.io\nOrigin: https://domain.io:123\r\n\r\n"
		reader := strings.NewReader(body)
		bufferSize := len(body) * 3
		buffer := make([]byte, bufferSize)
		sut := newHttpProcessor(reader, buffer)
		sut.requestMethod = "CONNECT"
		p := make([]byte, len(body))
		_, err := sut.GetReader().Read(p)
		length, ok := sut.GetContentLength()
		Expect(length).To(Equal(int64(15632)))
		Expect(ok).To(BeTrue())
		Expect(string(p)).To(Equal(body))
		Expect(err).To(Not(HaveOccurred()))
	})

	It("should only read what's in the request buffer when request content-length is missing", func() {
		for _, expectedHeader := range []string{"a.b.com", "tunnel.test.domain.io"} {
			body := "POST / HTTP/1.1\r\nContent-Type: application/json\r\nHost: domain.io\nOrigin: https://domain.io:123\r\n\r\nBody is here"
			oldHeader := "domain.io"
			reader := strings.NewReader(body)
			bufferSize := len(body) * 3
			buffer := make([]byte, bufferSize)
			sut := newHttpProcessor(reader, buffer)
			sut.SetHostHeader(expectedHeader)
			host, err := sut.GetHost()
			Expect(err).To(Not(HaveOccurred()))
			Expect(host, expectedHeader)

			origin := sut.headers["Origin"][0]
			Expect(origin, "https://"+expectedHeader+":123")

			p := make([]byte, len(body)+2*(len(expectedHeader)-len(oldHeader)))
			_, err = sut.GetReader().Read(p)
			Expect(string(p)).To(Equal(strings.Replace(body, oldHeader, expectedHeader, -1)))
			Expect(err).To(Not(HaveOccurred()))
		}
	})

	It("should process when buffer size is larger than body", func() {
		for _, expectedHeader := range []string{"a.b.com", "tunnel.test.domain.io"} {
			body := "POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 12\r\nHost: domain.io\nOrigin: https://domain.io:123\r\n\r\nBody is here"
			oldHeader := "domain.io"
			reader := strings.NewReader(body)
			bufferSize := len(body) * 3
			buffer := make([]byte, bufferSize)
			sut := newHttpProcessor(reader, buffer)
			sut.SetHostHeader(expectedHeader)
			host, err := sut.GetHost()
			Expect(err).To(Not(HaveOccurred()))
			Expect(host, expectedHeader)

			origin := sut.headers["Origin"][0]
			Expect(origin, "https://"+expectedHeader+":123")

			p := make([]byte, len(body)+2*(len(expectedHeader)-len(oldHeader)))
			_, err = sut.GetReader().Read(p)
			Expect(string(p)).To(Equal(strings.Replace(body, oldHeader, expectedHeader, -1)))
			Expect(err).To(Not(HaveOccurred()))
		}
	})

	It("should process chunked payload when buffer size is larger than body", func() {
		for _, expectedHeader := range []string{"a.b.com", "tunnel.test.domain.io"} {
			body := "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\nHost: domain.io\r\n\r\n7\r\nMozilla\r\n9\r\nDeveloper\r\n7\r\nNetwork\r\n0\r\n\r\n"
			oldHeader := "domain.io"
			reader := strings.NewReader(body)
			bufferSize := len(body) * 3
			buffer := make([]byte, bufferSize)
			sut := newHttpProcessor(reader, buffer)
			sut.SetHostHeader(expectedHeader)
			host, err := sut.GetHost()
			Expect(err).To(Not(HaveOccurred()))
			Expect(host, expectedHeader)

			p := make([]byte, len(body)+len(expectedHeader)-len(oldHeader))
			_, err = io.ReadFull(sut.GetReader(), p)
			Expect(string(p)).To(Equal(strings.Replace(body, oldHeader, expectedHeader, 1)))
			Expect(err).To(Not(HaveOccurred()))
		}
	})

	It("should process chunked payload when buffer size is equal to body", func() {
		for _, expectedHeader := range []string{"a.b.com", "tunnel.test.domain.io"} {
			body := "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\nHost: domain.io\r\n\r\n7\r\nMozilla\r\n9\r\nDeveloper\r\n7\r\nNetwork\r\n0\r\n\r\n"
			oldHeader := "domain.io"

			reader := strings.NewReader(body)
			bufferSize := len(body)
			buffer := make([]byte, bufferSize)
			sut := newHttpProcessor(reader, buffer)
			sut.SetHostHeader(expectedHeader)

			p := make([]byte, len(body)+len(expectedHeader)-len(oldHeader))
			_, err := io.ReadFull(sut.GetReader(), p)
			Expect(err).To(Not(HaveOccurred()))
			Expect(string(p)).To(Equal(strings.Replace(body, oldHeader, expectedHeader, 1)))
			Expect(sut.GetHost()).To(Equal(expectedHeader))
		}
	})

	It("should process chunked payload when buffer size is smaller than body", func() {
		for _, expectedHeader := range []string{"a.b.com", "tunnel.test.domain.io"} {
			body := "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\nHost: domain.io\r\n\r\n7\r\nMozilla\r\n9\r\nDeveloper\r\n7\r\nNetwork\r\n0\r\n\r\n"
			oldHeader := "domain.io"
			reader := strings.NewReader(body)
			bufferSize := len(body) - 40
			buffer := make([]byte, bufferSize)
			sut := newHttpProcessor(reader, buffer)
			Expect(sut.GetHost()).To(Equal(oldHeader))
			sut.SetHostHeader(expectedHeader)
			Expect(sut.GetHost()).To(Equal(expectedHeader))

			p := make([]byte, len(body)+len(expectedHeader)-len(oldHeader))
			_, err := io.ReadFull(sut.GetReader(), p)
			Expect(string(p)).To(Equal(strings.Replace(body, oldHeader, expectedHeader, 1)))
			Expect(err).To(Not(HaveOccurred()))
		}
	})

	It("should process chunked payload when buffer size is smaller than input buffer `p`", func() {
		for _, expectedHeader := range []string{"a.b.com", "tunnel.test.domain.io"} {
			body := "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\nHost: domain.io\r\n\r\n7\r\nMozilla\r\n9\r\nDeveloper\r\n7\r\nNetwork\r\n0\r\n\r\n"
			oldHeader := "domain.io"
			reader := strings.NewReader(body)
			p := make([]byte, len(body)+len(expectedHeader)-len(oldHeader)+50)
			bufferSize := len(p) - 10
			buffer := make([]byte, bufferSize)
			sut := newHttpProcessor(reader, buffer)
			Expect(sut.GetHost()).To(Equal(oldHeader))
			sut.SetHostHeader(expectedHeader)
			Expect(sut.GetHost()).To(Equal(expectedHeader))
			_, err := io.ReadAtLeast(sut.GetReader(), p, len(body)+len(expectedHeader)-len(oldHeader))
			Expect(string(p[:len(p)-50])).To(Equal(strings.Replace(body, oldHeader, expectedHeader, 1)))
			Expect(err).To(Not(HaveOccurred()))
		}
	})

	It("should process chunked payload when buffer is smaller than input size and both are smaller than payload", func() {
		for _, expectedHeader := range []string{"a.b.com", "tunnel.test.domain.io"} {
			body := "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\nHost: domain.io\r\n\r\n7\r\nMozilla\r\n9\r\nDeveloper\r\n7\r\nNetwork\r\n102\r\nNetworkABCNetworkNetworkABCNetworkNetworkABCNetworkNetworkABCNetworkNetworkABCNetworkNetworkABCNetwork\r\n0\r\n\r\n"
			oldHeader := "domain.io"
			reader := strings.NewReader(body)
			p := make([]byte, len(body)+len(expectedHeader)-len(oldHeader))
			bufferSize := 130
			buffer := make([]byte, bufferSize)
			sut := newHttpProcessor(reader, buffer)
			Expect(sut.GetHost()).To(Equal(oldHeader))
			sut.SetHostHeader(expectedHeader)
			Expect(sut.GetHost()).To(Equal(expectedHeader))
			n, err := sut.GetReader().Read(p[:130])
			c := n
			Expect(c).To(BeNumerically(">", 0))
			Expect(c).To(BeNumerically("<=", 130))
			Expect(err).To(Not(HaveOccurred()))
			n, err = sut.GetReader().Read(p[c:200])
			c += n
			Expect(c).To(BeNumerically(">", 0))
			Expect(c).To(BeNumerically("<=", 200))
			Expect(err).To(Not(HaveOccurred()))
			n, err = sut.GetReader().Read(p[c:])
			Expect(n).To(BeNumerically(">", 0))
			c += n
			Expect(err).To(Not(HaveOccurred()))
			Expect(string(p)).To(Equal(strings.Replace(body, oldHeader, expectedHeader, 1)))
		}
	})

	It("should process when buffer size is equal to body", func() {
		for _, expectedHeader := range []string{"a.b.com", "tunnel.test.domain.io"} {
			body := "POST / HTTP/1.1\r\nContent-Length: 12\r\nContent-Type: application/json\r\nHost: domain.io\r\n\r\nBody is here"
			oldHeader := "domain.io"

			reader := strings.NewReader(body)
			bufferSize := len(body)
			buffer := make([]byte, bufferSize)
			sut := newHttpProcessor(reader, buffer)
			sut.SetHostHeader(expectedHeader)

			p := make([]byte, len(body)+len(expectedHeader)-len(oldHeader))
			_, err := sut.GetReader().Read(p)
			Expect(err).To(Not(HaveOccurred()))
			Expect(string(p)).To(Equal(strings.Replace(body, oldHeader, expectedHeader, 1)))
			Expect(sut.GetHost()).To(Equal(expectedHeader))
		}
	})

	It("should process when buffer size is smaller than body", func() {
		for _, expectedHeader := range []string{"a.b.com", "tunnel.test.domain.io"} {
			body := "POST / HTTP/1.1\r\nContent-Length: 12\r\nContent-Type: application/json\r\nHost: domain.io\r\n\r\nBody is here"
			oldHeader := "domain.io"
			reader := strings.NewReader(body)
			bufferSize := len(body) - 10
			buffer := make([]byte, bufferSize)
			sut := newHttpProcessor(reader, buffer)
			Expect(sut.GetHost()).To(Equal(oldHeader))
			sut.SetHostHeader(expectedHeader)
			Expect(sut.GetHost()).To(Equal(expectedHeader))

			p := make([]byte, len(body)+len(expectedHeader)-len(oldHeader))
			_, err := io.ReadFull(sut.GetReader(), p)

			Expect(string(p)).To(Equal(strings.Replace(body, oldHeader, expectedHeader, 1)))
			Expect(err).To(Not(HaveOccurred()))
		}
	})

	It("should process when bufferSize < p", func() {
		for _, expectedHeader := range []string{"a.b.com", "tunnel.test.domain.io"} {
			body := "POST / HTTP/1.1\r\nContent-Length: 12\r\nContent-Type: application/json\r\nHost: domain.io\r\n\r\nBody is here"
			oldHeader := "domain.io"
			reader := strings.NewReader(body)
			p := make([]byte, len(body)+len(expectedHeader)-len(oldHeader)+50)
			bufferSize := len(p) - 10
			buffer := make([]byte, bufferSize)
			sut := newHttpProcessor(reader, buffer)
			Expect(sut.GetHost()).To(Equal(oldHeader))
			sut.SetHostHeader(expectedHeader)
			Expect(sut.GetHost()).To(Equal(expectedHeader))
			_, err := sut.GetReader().Read(p)
			Expect(string(p[:len(p)-50])).To(Equal(strings.Replace(body, oldHeader, expectedHeader, 1)))
			Expect(err).To(Not(HaveOccurred()))
		}
	})

	It("should process when buffer size is smaller than body and Read all body", func() {
		body := "POST / HTTP/1.1\r\nContent-Length: 12\r\nContent-Type: application/json\r\nHost: domain.io\r\n\r\nBody is here"
		oldHeader := "domain.io"
		for _, expectedHeader := range []string{"a.b.com", "tunnel.test.domain.io"} {
			reader := strings.NewReader(body)
			bufferSize := len(body) - 10
			buffer := make([]byte, bufferSize)
			sut := newHttpProcessor(reader, buffer)
			sut.SetHostHeader(expectedHeader)

			p := make([]byte, len(body)+len(expectedHeader)-len(oldHeader))
			_, err := sut.GetReader().Read(p[:len(p)-10])
			Expect(err).To(Not(HaveOccurred()))
			_, err = sut.GetReader().Read(p[len(p)-10:])
			Expect(err).To(Not(HaveOccurred()))
			Expect(string(p)).To(Equal(strings.Replace(body, oldHeader, expectedHeader, 1)))
			Expect(sut.GetHost()).To(Equal(expectedHeader))
		}
	})

	It("should parse Host without modifying headers", func() {
		body := "POST / HTTP/1.1\r\nContent-Length: 12\r\nContent-Type: application/json\r\nHost: domain.io\r\n\r\nBody is here"
		header := "domain.io"
		reader := strings.NewReader(body)
		bufferSize := len(body) - 10
		buffer := make([]byte, bufferSize)
		sut := newHttpProcessor(reader, buffer)
		p := make([]byte, len(body))
		_, err := io.ReadFull(sut.GetReader(), p[:len(p)-10])
		Expect(err).To(Not(HaveOccurred()))
		_, err = io.ReadFull(sut.GetReader(), p[len(p)-10:])
		Expect(err).To(Not(HaveOccurred()))
		Expect(string(p)).To(Equal(body))
		Expect(sut.GetHost()).To(Equal(header))

	})

	It("should work with io.Copy", func() {
		body := "POST / HTTP/1.1\r\nContent-Length: 12\r\nContent-Type: application/json\r\nHost: domain.io\r\n\r\nBody is here"
		reader := strings.NewReader(body)
		bufferSize := len(body) - 10
		buffer := make([]byte, bufferSize)
		sut := newHttpProcessor(reader, buffer)

		var buf bytes.Buffer
		n, err := io.Copy(&buf, sut)
		Expect(n).To(Equal(int64(len(body))))
		Expect(buf.String()).To(Equal(body))
		Expect(err).To(Not(HaveOccurred()))

	})

	It("should Read body without Host header", func() {
		body := "POST / HTTP/1.1\r\nContent-Length: 12\r\nContent-Type: application/json\r\nAuthorization: domain.io\r\n\r\nBody is here"

		reader := strings.NewReader(body)
		bufferSize := len(body) - 10
		buffer := make([]byte, bufferSize)
		sut := newHttpProcessor(reader, buffer)
		host, err := sut.GetHost()
		Expect(err).To(HaveOccurred())
		Expect(host).To(Equal(""))

		p := make([]byte, len(body))
		_, err = sut.GetReader().Read(p[:len(p)-10])
		Expect(err).To(Not(HaveOccurred()))
		_, err = sut.GetReader().Read(p[len(p)-10:])
		Expect(err).To(Not(HaveOccurred()))
		// Expect(err).To(Or(Not(HaveOccurred()), BeEquivalentTo(io.EOF)))
		Expect(string(p)).To(Equal(body))
		n, err := sut.GetReader().Read(p[len(p)-10:])

		// Subsequent call should return error io.EOF with 0 bytes Read
		Expect(n).To(Equal(0))
		Expect(err).To(BeEquivalentTo(io.EOF))

	})

	It("should parse Host without explicit Read", func() {
		body := "POST / HTTP/1.1\r\nContent-Length: 12\r\nContent-Type: application/json\r\nHost: domain.io\r\n\r\nBody is here"
		header := "domain.io"
		reader := strings.NewReader(body)
		bufferSize := len(body)
		buffer := make([]byte, bufferSize)
		sut := newHttpProcessor(reader, buffer)
		host, err := sut.GetHost()
		Expect(err).To(Not(HaveOccurred()))
		Expect(host).To(Equal(header))
	})

})
