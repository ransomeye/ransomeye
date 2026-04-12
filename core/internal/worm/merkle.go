package worm

import (
	"crypto/sha256"
)

// HashLeaf computes the RFC6962 Merkle leaf hash.
func HashLeaf(data []byte) []byte {
	h := sha256.Sum256(append([]byte{0x00}, data...))
	return h[:]
}

// HashNode computes the RFC6962 Merkle internal node hash.
func HashNode(left, right []byte) []byte {
	combined := append([]byte{0x01}, append(left, right...)...)
	h := sha256.Sum256(combined)
	return h[:]
}
