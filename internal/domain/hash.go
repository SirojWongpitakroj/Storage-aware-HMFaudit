package domain

import (
	"crypto/sha256"
)

// HashPair is SHA-256 over prefix || left [|| right]. The message is assembled in a stack buffer, so
// the usual node hash (a short prefix and two digests) allocates nothing.
func HashPair(prefix string, left, right *[32]byte) [32]byte {
	var stack [128]byte
	combined := append(stack[:0], prefix...)
	combined = append(combined, (*left)[:]...)
	if right != nil {
		combined = append(combined, (*right)[:]...)
	}
	return sha256.Sum256(combined)
}
