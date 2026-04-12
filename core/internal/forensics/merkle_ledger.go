package forensics

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"

	crypto "ransomeye/core/internal/crypto"
)

const (
	LeafPrefix     = byte(0x00)
	InternalPrefix = byte(0x01)
)

type MerkleLedger struct {
	// leaves MUST NEVER be exposed or mutated outside Append()
	leaves [][]byte
}

func HashLeaf(data []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte{LeafPrefix})
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func HashInternal(left, right []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte{InternalPrefix})
	_, _ = h.Write(left)
	_, _ = h.Write(right)
	return h.Sum(nil)
}

func BuildMerkleRoot(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 {
		sum := sha256.Sum256(nil)
		return sum[:]
	}
	if n == 1 {
		return HashLeaf(leaves[0])
	}

	k := largestPowerOfTwoLessThan(n)
	return HashInternal(
		BuildMerkleRoot(leaves[:k]),
		BuildMerkleRoot(leaves[k:]),
	)
}

func (m *MerkleLedger) Append(data []byte) {
	if m == nil {
		return
	}

	hash := HashLeaf(data)

	copyHash := make([]byte, len(hash))
	copy(copyHash, hash)

	m.leaves = append(m.leaves, copyHash)
}

func (m *MerkleLedger) Verify(root []byte) bool {
	computed := BuildMerkleRoot(m.leaves)
	return bytes.Equal(computed, root)
}

func SignRoot(root []byte, priv ed25519.PrivateKey) []byte {
	return ed25519.Sign(priv, root)
}

func (m *MerkleLedger) Snapshot(prevRoot []byte, priv ed25519.PrivateKey) ([]byte, []byte) {
	leavesCopy := make([][]byte, len(m.leaves))
	for i := range m.leaves {
		h := make([]byte, len(m.leaves[i]))
		copy(h, m.leaves[i])
		leavesCopy[i] = h
	}

	currentRoot := BuildMerkleRoot(leavesCopy)

	// chain: H(prevRoot || currentRoot)
	combined := make([]byte, 0, len(prevRoot)+len(currentRoot))
	combined = append(combined, prevRoot...)
	combined = append(combined, currentRoot...)

	finalRoot := HashLeaf(combined)

	sig := SignRoot(finalRoot, priv)

	return finalRoot, sig
}

func (m *MerkleLedger) VerifySnapshot(
	prevRoot []byte,
	finalRoot []byte,
	sig []byte,
	pub ed25519.PublicKey,
) bool {
	if len(m.leaves) == 0 {
		return false
	}

	// recompute current root
	currentRoot := BuildMerkleRoot(m.leaves)

	// verify chain
	if !crypto.VerifyChainedRoot(prevRoot, currentRoot, finalRoot) {
		return false
	}

	// verify signature
	if !crypto.VerifyRoot(finalRoot, sig, pub) {
		return false
	}

	return true
}

func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k < n-1 {
		k <<= 1
	}
	return k
}
