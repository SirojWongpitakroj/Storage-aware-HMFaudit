package domain

import (
	"crypto/sha256"
	"testing"
)

func TestHashPairMatchesPlainConcatenation(t *testing.T) {
	left, right := sha256.Sum256([]byte("l")), sha256.Sum256([]byte("r"))
	for _, prefix := range []string{"", "NODE", "LEAF", "a-prefix-longer-than-the-stack-buffer-slack-" +
		"a-prefix-longer-than-the-stack-buffer-slack-a-prefix-longer-than-the-stack-buffer-slack"} {
		want := sha256.Sum256(append(append([]byte(prefix), left[:]...), right[:]...))
		if got := HashPair(prefix, &left, &right); got != want {
			t.Fatalf("prefix %q: pair hash differs", prefix)
		}
		want = sha256.Sum256(append([]byte(prefix), left[:]...))
		if got := HashPair(prefix, &left, nil); got != want {
			t.Fatalf("prefix %q: single hash differs", prefix)
		}
	}
}

func TestHashPairDoesNotAllocate(t *testing.T) {
	left, right := sha256.Sum256([]byte("l")), sha256.Sum256([]byte("r"))
	if allocs := testing.AllocsPerRun(100, func() { _ = HashPair("NODE", &left, &right) }); allocs != 0 {
		t.Fatalf("HashPair allocated %v times per call", allocs)
	}
}
