package spki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"github.com/eadmund/sexprs"
	"testing"
)

func TestHash(t *testing.T) {
	hasher := sha256.New()
	hasher.Write([]byte("This is a test; it is only a test"))
	h1 := Hash{"sha256", hasher.Sum(nil), nil}
	h2 := Hash{"sha256", hasher.Sum(nil), nil}
	if !h1.Equal(h2) {
		t.Fatal("Equal hashes are not Equal()")
	}
	sexp, _, err := sexprs.Parse([]byte("(hash sha512 #7356f5d518d0a4f02741fee41b851cacfd428f02dc6c92557807dc6b51a97c2f3404121eb752a7c14819143a9273aff47bef5f7305e1476f4ab338832bc9d022#)"))
	if err != nil {
		t.Fatal("Error reading hash S-expression", err)
	}
	h1, err = EvalHash(sexp)
	if err != nil {
		t.Fatal("Error evaluating hash S-expression", err)
	}
	if h1.URIs != nil {
		t.Fatal("URIs for non-URI-having hash")
	}
	h1, err = EvalHash(sexprs.List{})
	if err == nil {
		t.Fatal("EvalHash didn't return an error when passed an empty list", h1)
	}
	sexp, _, err = sexprs.Parse([]byte("(hash sha512 #7356f5d518d0a4f02741fee41b851cacfd428f02dc6c92557807dc6b51a97c2f3404121eb752a7c14819143a9273aff47bef5f7305e1476f4ab338832bc9d022# (uris \"http://example.com\"))"))
	h1, err = EvalHash(sexp)
	if h1.URIs == nil {
		t.Fatal("No URIs for URI-having hash")
	}
	//t.Log(h1.URIs)
	//t.Log(h.Sexp())
}

func TestECDSA256Key(t *testing.T) {
	sexp, _, err := sexprs.Parse([]byte("(public-key (ecdsa-sha2 (curve p256) (x |vSmjExRs7DcpfWee3jTjx67KYHirQHO1Emti/UN2r5w=|) (y |CIZuZoyB38XoIyREM0fhDdsSc/jZEVLpLYeqVPje9Mc=|)))"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := EvalPublicKey(sexp)
	if err != nil {
		t.Fatal(err)
	}
	_ = key
	//t.Log(key)
}

func TestECDSASHA2PrivateKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki_key := PrivateKey{HashKey{}, *key}
	//t.Log(spki_key.String())
	string_key, _, err := sexprs.Parse([]byte(spki_key.String()))
	if err != nil {
		t.Fatal(err)
	}
	byte_key, _, err := sexprs.Parse(spki_key.Sexp().Pack())
	if err != nil {
		t.Fatal(err)
	}
	if !string_key.Equal(byte_key) {
		t.Fatal("String- and byte-read keys differ")
	}
	eval_key, err := EvalPrivateKey(string_key)
	if err != nil {
		t.Fatal(err)
	}
	if key.X.Cmp(eval_key.X) != 0 {
		t.Fatal("Differing X: %s vs. %x", key.X, eval_key.X)
	}
	if key.Y.Cmp(eval_key.Y) != 0 {
		t.Fatal("Differing X: %s vs. %x", key.Y, eval_key.Y)
	}
	if key.D.Cmp(eval_key.D) != 0 {
		t.Fatal("Differing X: %s vs. %x", key.D, eval_key.D)
	}
}

func TestGeneratePrivateKey(t *testing.T ) {
	_, err := GeneratePrivateKey("ecdsa-sha2 (curve p256)")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignature(t *testing.T) {
	key, err := GeneratePrivateKey("ecdsa-sha2 (curve p256)")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := key.Sign(key.Sexp())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(sig.String())
}
