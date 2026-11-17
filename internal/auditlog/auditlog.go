// Package auditlog holds the pieces of a stored log that the ingest and
// auditor commands must agree on: how a log is sealed and how its leaf digest
// is computed from the stored columns.
package auditlog

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// KeySize is the AES-256 key length in bytes.
const KeySize = 32

const digestDomain = "HMFLOG1"

// Seal encrypts plaintext with AES-256-GCM under a fresh random nonce. The
// associated data binds the ciphertext to the log's attributes and ID.
func Seal(key, plaintext, associatedData []byte) (ciphertext, tag, nonce []byte, err error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("auditlog: nonce: %w", err)
	}
	sealed := aead.Seal(nil, nonce, plaintext, associatedData)
	split := len(sealed) - aead.Overhead()
	return sealed[:split], sealed[split:], nonce, nil
}

// Open decrypts and authenticates a sealed log.
func Open(key, ciphertext, tag, nonce, associatedData []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)
	return aead.Open(nil, nonce, sealed, associatedData)
}

// OpenUnauthenticated decrypts a GCM-sealed log WITHOUT checking its tag or
// associated data. AES-GCM encrypts with counter mode starting at counter 2, so
// the keystream can be reproduced without authenticating. The result is only
// for showing what a log that failed verification now contains; it must never
// be trusted as the log's content.
func OpenUnauthenticated(key, ciphertext, nonce []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("auditlog: key must be %d bytes, got %d", KeySize, len(key))
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("auditlog: nonce must be 12 bytes, got %d", len(nonce))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	copy(iv, nonce)
	iv[aes.BlockSize-1] = 2
	plain := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(plain, ciphertext)
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("auditlog: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Digest is the leaf committed in the Hierarchical Merkle Forest for one
// stored log. It covers every stored column (ciphertext, tag, nonce and
// associated data, which carries the log's attributes), each length-prefixed,
// so changing any of them changes the digest.
func Digest(ciphertext, tag, nonce, associatedData []byte) [32]byte {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(digestDomain))
	for _, field := range [][]byte{ciphertext, tag, nonce, associatedData} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write(field)
	}
	var digest [32]byte
	copy(digest[:], hasher.Sum(nil))
	return digest
}
