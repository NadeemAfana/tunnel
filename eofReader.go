package main

import "io"

// Reader that keeps track of EOF
type eofReader struct {
	r   io.Reader
	EOF bool
}

func (reader *eofReader) Read(p []byte) (n int, err error) {
	n, err = reader.r.Read(p)
	if err == io.EOF {
		reader.EOF = true
	}
	return n, err
}