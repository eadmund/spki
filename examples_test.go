package spki_test

import (
	"fmt"
	"github.com/eadmund/sexprs"
	"github.com/eadmund/spki"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T ) {
	_, err := spki.GeneratePrivateKey("(ecdsa-sha2 (curve p256))")
	if err != nil {
		t.Fatal(err)
	}
}

func Example_PrivateKey() {
	key, err := spki.GeneratePrivateKey("(ecdsa-sha2 (curve p256))")
	if err != nil {
		panic(err)
	}
	message := sexprs.Atom{Value: []byte("This is a message for signing")}
	signature, err := key.Sign(message)
	if err != nil {
		panic(err)
	}
	fmt.Println(signature)
	// // Output:
}