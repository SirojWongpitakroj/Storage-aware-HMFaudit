package auditlog

import (
	"bytes"
	"testing"
)

func testKey() []byte { return bytes.Repeat([]byte{7}, KeySize) }

func TestSealOpenRoundTrip(t *testing.T) {
	ciphertext, tag, nonce, err := Seal(testKey(), []byte("Update row: 501601"), []byte("ad"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Open(testKey(), ciphertext, tag, nonce, []byte("ad"))
	if err != nil || string(plain) != "Update row: 501601" {
		t.Fatalf("Open = %q, %v", plain, err)
	}
}

func TestOpenUnauthenticatedMatchesOpenAndShowsTampering(t *testing.T) {
	message := []byte("Update row: 501601 and a longer tail that spans several AES blocks of text")
	ciphertext, tag, nonce, err := Seal(testKey(), message, []byte("ad"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := OpenUnauthenticated(testKey(), ciphertext, nonce)
	if err != nil || !bytes.Equal(plain, message) {
		t.Fatalf("OpenUnauthenticated of an honest log = %q, %v; want %q", plain, err, message)
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0xff
	if _, err := Open(testKey(), tampered, tag, nonce, []byte("ad")); err == nil {
		t.Fatal("Open accepted a tampered ciphertext")
	}
	shown, err := OpenUnauthenticated(testKey(), tampered, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if shown[0] != message[0]^0xff || !bytes.Equal(shown[1:], message[1:]) {
		t.Fatalf("unauthenticated view of a tampered log should differ only in byte 0: %q", shown)
	}
}

func TestDigestCoversEveryColumn(t *testing.T) {
	base := Digest([]byte("c"), []byte("t"), []byte("n"), []byte("a"))
	for name, changed := range map[string][32]byte{
		"ciphertext": Digest([]byte("x"), []byte("t"), []byte("n"), []byte("a")),
		"tag":        Digest([]byte("c"), []byte("x"), []byte("n"), []byte("a")),
		"nonce":      Digest([]byte("c"), []byte("t"), []byte("x"), []byte("a")),
		"ad":         Digest([]byte("c"), []byte("t"), []byte("n"), []byte("x")),
	} {
		if changed == base {
			t.Errorf("changing the %s did not change the digest", name)
		}
	}
	// Field boundaries are part of the digest.
	if Digest([]byte("ab"), []byte("c"), nil, nil) == Digest([]byte("a"), []byte("bc"), nil, nil) {
		t.Error("moving a byte between fields did not change the digest")
	}
}
