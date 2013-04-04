// Copyright 2013 Robert A. Uhl.  All rights reserved.
// Use of this source code is governed by an MIT-style license which may
// be found in the LICENSE file.

package spki

import (
	"bytes"
	//"crypto/ecdsa"
	//"crypto/elliptic"
	//"crypto/sha256"
	//"crypto/sha512"
	"fmt"
	"github.com/eadmund/sexprs"
	//"hash"
	"math/big"
	//"net/url"
)

// Signature represents an ECDSA signature.  Neither DSA nor RSA are
// currently supported.  Should RSA be supported, expect Signature to
// become an interface.
type Signature struct {
	Hash      Hash
	Principal *PublicKey
	R, S      *big.Int
}

type HashNotFoundError struct {
	Hash Hash
}

func (h HashNotFoundError) Error() string {
	return fmt.Sprintf("Hash value %s not found", h.Hash)
}

var (
	signatureAtom = sexprs.Atom{Value: []byte("signature")}
)

// EvalSignature converts a signature S-expression to a Signature.  An
// ECDSA signature looks like:
//    (signature (hash sha256 |...|) PRINCIPAL (ecdsa |...| |...|))
// where PRINCIPAL is either a public key or the hash of a public key.
// If PRINCIPAL is a hash, lookupFunc is used to look it up; if it is nil
// or returns nil, then EvalSignature returns a HashNotFoundError.
func EvalSignature(s sexprs.Sexp, lookupFunc func(Hash) *PublicKey) (sig *Signature, err error) {
	l, ok := s.(sexprs.List)
	if !ok {
		return nil, fmt.Errorf("Signature S-expression must be a list")
	}
	if len(l) != 4 || !signatureAtom.Equal(l[0]) {
		return nil, fmt.Errorf("Signature S-expression must be of the form (signature (hash sha256 |...|) PRINCIPAL (ecdsa |...| |...|))")
	}

	sig = new(Signature)
	sig.Hash, err = EvalHash(l[1])
	if err != nil {
		return nil, err
	}
	principal, ok := l[2].(sexprs.List)
	if !ok {
		return nil, fmt.Errorf("Principal must be either a hash or a public key")
	}
	principalFirst, ok := principal[0].(sexprs.Atom)
	if !ok {
		return nil, fmt.Errorf("Principal must be either a hash or a public key")
	}
	switch string(principalFirst.Value) {
	case "hash":
		hash, err := EvalHash(principal)
		if err != nil {
			return nil, err
		}
		sig.Principal = lookupFunc(hash)
		if sig.Principal == nil {
			return nil, HashNotFoundError{hash}
		}
	case "public-key":
		sig.Principal, err = EvalPublicKey(principal)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("Principal must be either a hash or a public key")
	}
	sigVal, ok := l[3].(sexprs.List)
	if !ok || len(sigVal) != 3 {
		return nil, fmt.Errorf("Signature value must be of the form (ecdsa-sha2 (r |...|) (s |...|))")
	}
	sigId, ok := sigVal[0].(sexprs.Atom)
	if !ok || !bytes.Equal(sigId.Value, []byte("ecdsa-sha2")) {
		return nil, fmt.Errorf("Signature ID must equal ecdsa-sha2")
	}
	sig.R, err = evalNamedBigInt("r", sigVal[1])
	if err != nil {
		return nil, err
	}
	sig.S, err = evalNamedBigInt("s", sigVal[1])
	if err != nil {
		return nil, err
	}
	return sig, nil
}
