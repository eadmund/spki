package spki

import (
	"testing"
	"crypto/sha256"
	"github.com/eadmund/sexprs"
)

func TestHash(t *testing.T) {
	hasher := sha256.New()
	hasher.Write([]byte("This is a test; it is only a test"))
	h1 := Hash{"sha256", hasher.Sum(nil)}
	h2 := Hash{"sha256", hasher.Sum(nil)}
	if !h1.Equal(h2) {
		t.Fatal("Equal hashes are not Equal()")
	}
	sexp, _, err := sexprs.ReadBytes([]byte("(hash sha512 #7356f5d518d0a4f02741fee41b851cacfd428f02dc6c92557807dc6b51a97c2f3404121eb752a7c14819143a9273aff47bef5f7305e1476f4ab338832bc9d022#)"))
	if err != nil {
		t.Fatal("Error reading hash S-expression", err)
	}
	h1, err = EvalHash(sexp)
	if err != nil {
		t.Fatal("Error evaluation hash S-expression", err)
	}
	//t.Log(h1.Sexp())
	//t.Log(h.Sexp())
}