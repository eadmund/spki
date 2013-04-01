package spki

import (
	"testing"
	"crypto/sha256"
)

func TestHash(t *testing.T) {
	hasher := sha256.New()
	hasher.Write([]byte("This is a test; it is only a test"))
	h1 := Hash{"sha256", hasher.Sum(nil)}
	h2 := Hash{"sha256", hasher.Sum(nil)}
	if !h1.Equal(h2) {
		t.Fatal("Equal hashes are not Equal()")
	}
	//t.Log(h.Sexp())
}