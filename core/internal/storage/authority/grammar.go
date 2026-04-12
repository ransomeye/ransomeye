package authority

import (
	"encoding/binary"
	"fmt"
)

const (
	fieldAbsent = 0x00
	fieldPresent = 0x01
)

func appendU16BE(b []byte, v uint16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return append(b, buf[:]...)
}

func appendU32BE(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}

func appendU64BE(b []byte, v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return append(b, buf[:]...)
}

func appendASCIIBytes(b []byte, lit string) []byte {
	return append(b, lit...)
}

func appendTextField(b []byte, s string) []byte {
	utf8 := []byte(s)
	b = appendU32BE(b, uint32(len(utf8)))
	return append(b, utf8...)
}

func appendEnumField(b []byte, s string) []byte {
	return appendTextField(b, s)
}

func appendBytesField(b []byte, p []byte) []byte {
	b = appendU32BE(b, uint32(len(p)))
	return append(b, p...)
}

func appendHash32Field(b []byte, h [32]byte) []byte {
	if len(h) != 32 {
		panic("hash32 wrong length")
	}
	return append(b, h[:]...)
}

func appendUint64Field(b []byte, v uint64) []byte {
	return appendU64BE(b, v)
}

func appendPresentOrAbsentBytes(b []byte, p []byte) []byte {
	if p == nil {
		return append(b, fieldAbsent)
	}
	b = append(b, fieldPresent)
	return appendBytesField(b, p)
}

func appendPresentOrAbsentText(b []byte, s *string) []byte {
	if s == nil {
		return append(b, fieldAbsent)
	}
	b = append(b, fieldPresent)
	return appendTextField(b, *s)
}

func appendPresentOrAbsentHash32(b []byte, h *[32]byte) []byte {
	if h == nil {
		return append(b, fieldAbsent)
	}
	b = append(b, fieldPresent)
	return appendHash32Field(b, *h)
}

func appendPresentOrAbsentUint64(b []byte, v *uint64) []byte {
	if v == nil {
		return append(b, fieldAbsent)
	}
	b = append(b, fieldPresent)
	return appendUint64Field(b, *v)
}

func requireLen(name string, p []byte, want int) error {
	if len(p) != want {
		return fmt.Errorf("%s: length %d want %d", name, len(p), want)
	}
	return nil
}
