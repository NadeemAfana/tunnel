package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// TestAcquireDatagramDispatch verifies that acquireDatagram routes each
// payload size to the correct concrete type (and therefore the correct
// pool). The 2048-byte boundary is checked from both sides.
func TestAcquireDatagramDispatch(t *testing.T) {
	cases := []struct {
		name    string
		size    int
		wantBig bool
	}{
		{"zero", 0, false},
		{"one byte", 1, false},
		{"mtu-ish 1500", 1500, false},
		{"boundary minus one", udpSmallBufSize - 1, false},
		{"exactly boundary", udpSmallBufSize, false},
		{"boundary plus one", udpSmallBufSize + 1, true},
		{"jumbo 8192", 8192, true},
		{"near max", udpMaxDatagramSize - 1, true},
		{"max", udpMaxDatagramSize, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xAB}, c.size)
			d := acquireDatagram(payload)
			defer d.release()

			_, isLarge := d.(largeDatagram)
			_, isSmall := d.(smallDatagram)
			if c.wantBig && !isLarge {
				t.Fatalf("size=%d: want largeDatagram, got %T", c.size, d)
			}
			if !c.wantBig && !isSmall {
				t.Fatalf("size=%d: want smallDatagram, got %T", c.size, d)
			}
			if len(d.bytes()) != c.size {
				t.Fatalf("size=%d: d.bytes() len = %d, want %d", c.size, len(d.bytes()), c.size)
			}
			if !bytes.Equal(d.bytes(), payload) {
				t.Fatalf("size=%d: d.bytes() does not match payload", c.size)
			}
		})
	}
}

// TestAcquireDatagramReleaseReusable confirms that the pool round-trip is
// not corrupted by release(). After release, the next acquire of the same
// size class must still produce a usable buffer.
func TestAcquireDatagramReleaseReusable(t *testing.T) {
	for i := 0; i < 100; i++ {
		size := 256
		if i%2 == 1 {
			size = udpSmallBufSize + 256
		}
		payload := bytes.Repeat([]byte{byte(i)}, size)
		d := acquireDatagram(payload)
		if !bytes.Equal(d.bytes(), payload) {
			t.Fatalf("iteration %d: payload mismatch", i)
		}
		d.release()
	}
}

// TestReadPooledDatagramDispatch builds a length-prefixed wire frame for
// each size and confirms readPooledDatagram routes to the correct pool.
func TestReadPooledDatagramDispatch(t *testing.T) {
	cases := []struct {
		name    string
		size    int
		wantBig bool
	}{
		{"empty payload", 0, false},
		{"small 1500", 1500, false},
		{"exactly boundary", udpSmallBufSize, false},
		{"boundary plus one", udpSmallBufSize + 1, true},
		{"max", udpMaxDatagramSize, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			payload := bytes.Repeat([]byte{0xCD}, c.size)
			var hdr [2]byte
			binary.BigEndian.PutUint16(hdr[:], uint16(c.size))
			buf.Write(hdr[:])
			buf.Write(payload)

			d, err := readPooledDatagram(&buf)
			if err != nil {
				t.Fatalf("size=%d: readPooledDatagram error: %v", c.size, err)
			}
			defer d.release()

			_, isLarge := d.(largeDatagram)
			_, isSmall := d.(smallDatagram)
			if c.wantBig && !isLarge {
				t.Fatalf("size=%d: want largeDatagram, got %T", c.size, d)
			}
			if !c.wantBig && !isSmall {
				t.Fatalf("size=%d: want smallDatagram, got %T", c.size, d)
			}
			if !bytes.Equal(d.bytes(), payload) {
				t.Fatalf("size=%d: payload mismatch", c.size)
			}
		})
	}
}

// TestReadPooledDatagramOversized confirms the oversized-frame error path
// is reachable. uint16 max is 65535, which exceeds udpMaxDatagramSize.
func TestReadPooledDatagramOversized(t *testing.T) {
	var buf bytes.Buffer
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(udpMaxDatagramSize+1))
	buf.Write(hdr[:])

	_, err := readPooledDatagram(&buf)
	if !errors.Is(err, errOversizedFrame) {
		t.Fatalf("want errOversizedFrame, got %v", err)
	}
}

// TestReadPooledDatagramTruncated confirms that a truncated payload (EOF
// mid-read) propagates as io.ErrUnexpectedEOF rather than corrupting pool
// state. After the error, the next read still works.
func TestReadPooledDatagramTruncated(t *testing.T) {
	var buf bytes.Buffer
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], 1000)
	buf.Write(hdr[:])
	buf.Write(bytes.Repeat([]byte{0xEE}, 500)) // half the payload

	_, err := readPooledDatagram(&buf)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
	}

	// Next clean read must still work; the truncation path returned the
	// pool buffer correctly.
	var ok bytes.Buffer
	payload := bytes.Repeat([]byte{0x11}, 100)
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	ok.Write(hdr[:])
	ok.Write(payload)
	d, err := readPooledDatagram(&ok)
	if err != nil {
		t.Fatalf("recovery read failed: %v", err)
	}
	if !bytes.Equal(d.bytes(), payload) {
		t.Fatalf("recovery read payload mismatch")
	}
	d.release()
}
