// Copyright 2013 Robert A. Uhl.  All rights reserved.
// Use of this source code is governed by an MIT-style license which may
// be found in the LICENSE file.

package spki

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/eadmund/sexprs"
	"hash"
)

// A Hash represents the Hash of some value under Algorithm.  It may
// optionally have an array of associated URIs which may be used to
// help retrieve the hashed object.  Although the SPKI standard calls
// these URIs, they really are URLs, as they would be used to locate,
// not just indicate, the hashed object.
type Hash struct {
	Algorithm string // sha224, sha256, sha384 or sha512
	Hash      []byte // a byte slice of the appropriate length
	URIs      URIs   // zero or more associated URIs
}

// Sexp returns an S-expression representing the Hash h.  Calling
// s.Pack() will return h's canonical S-expression form.
func (h Hash) Sexp() (s sexprs.Sexp) {
	s = sexprs.List{sexprs.Atom{nil, []byte("hash")},
		sexprs.Atom{nil, []byte(h.Algorithm)},
		sexprs.Atom{nil, h.Hash}}
	return s
}

// String returns h's advanced S-expression form.
func (h Hash) String() string {
	return h.Sexp().String()
}

// Equal returns true if a & b are equivalent hash values, i.e. if
// they share the same Algorithm and the same Hash.  It ignores the
// optional URIs.
func (a Hash) Equal(b Hash) bool {
	return a.Algorithm == b.Algorithm && bytes.Equal(a.Hash, b.Hash)
}

var (
	// the atom found at the beginning of a hash S-expression
	hashAtom = sexprs.Atom{nil, []byte("hash")}
	// the atom found at the beginning of a uris S-expression
	urisAtom       = sexprs.Atom{nil, []byte("uris")}
	publicKeyAtom  = sexprs.Atom{nil, []byte("public-key")}
	privateKeyAtom = sexprs.Atom{nil, []byte("private-key")}
	ecdsa256Atom   = sexprs.Atom{nil, []byte("ecdsa-sha2")}
	ecdsa384Atom   = sexprs.Atom{nil, []byte("ecdsa-sha2")}
	// KnownHashes is a map of all known hash names to the associated hash
	// constructors.
	KnownHashes = make(map[string]func() hash.Hash)
)

// EvalHash converts a hash S-expression to its equivalent Hash struct.
func EvalHash(s sexprs.Sexp) (h Hash, err error) {
	switch s := s.(type) {
	case sexprs.List:
		if len(s) >= 3 && len(s) < 5 && hashAtom.Equal(s[0]) {
			algorithm, alg_ok := s[1].(sexprs.Atom)
			value, val_ok := s[2].(sexprs.Atom)
			if alg_ok && val_ok && validHash(algorithm.Value) {
				h = Hash{string(algorithm.Value),
					value.Value, nil}
				if len(s) == 4 {
					h.URIs, err = EvalURIs(s[3])
					if err != nil {
						return Hash{}, err
					}
				}
				return h, nil
			}
		}
	}
	return Hash{}, fmt.Errorf("Invalid hash expression")
}

func validHash(b []byte) bool {
	_, ok := KnownHashes[string(b)]
	return ok
}

func init() {
	KnownHashes["sha256"] = sha256.New
	KnownHashes["sha224"] = sha256.New224
	KnownHashes["sha512"] = sha512.New
	KnownHashes["sha384"] = sha512.New384
}
