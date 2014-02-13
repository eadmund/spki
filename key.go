// Copyright 2014 Robert A. Uhl.  All rights reserved.
// Use of this source code is governed by an MIT-style license which may
// be found in the LICENSE file.

package spki

import (
	"fmt"
	"github.com/eadmund/sexprs"
)

type Key interface {
	// Returns true if the key is just a hash.
	IsHash() bool
	// Returns the public key for the key: the key itself, if it's
	// already a public key; a public version of the key, if it's
	// a private key; or nil, if it is a hash without a key.
	PublicKey() (*PublicKey)
	// Returns the hash value of the key under a particular
	// algorithm, or an error if the key is just a hash and the
	// specified algorithm is not the algorithm used to generate
	// it.
	Hashed(algorithm string) ([]byte, error)
	// Returns the hash value of the key as per Hashed, but as a
	// Hash object.
	HashExp(algorithm string) (Hash, error)
	// Returns the SPKI signature algorithm of the key,
	// e.g. "ecdsa-sha256".  May be the empty string if unknown.
	SignatureAlgorithm() string
	// Returns the SPKI hash algorithm the key uses in signing,
	// e.g. "sha256".  May be the empty string if unknown.
	HashAlgorithm() string
	Equal(Key) bool
}

// A HashKey is just the hash value(s) of a key, without any public or
// private component; as such, it can only report its value under its
// own algorithm(s), and cannot be used to sign or verify anything.
type HashKey struct {
	Hashes []Hash
}

func (h HashKey) IsHash() bool {
	return true
}

func (h HashKey) PublicKey() *PublicKey {
	return nil
}

func (h HashKey) Hashed(algorithm string) ([]byte, error) {
	hash, err := h.HashExp(algorithm)
	return hash.Hash, err
}

func (h HashKey) HashExp(algorithm string) (hh Hash, err error) {
	for _, hash := range h.Hashes {
		if hash.Algorithm == algorithm {
			return hash, nil
		}
	}
	return hh, fmt.Errorf("No hash found for algorithm %s", algorithm)
}

// Hashed keys never have any known signature algorithm.
func (h HashKey) SignatureAlgorithm() string {
	return ""
}

// Hashed keys never have any known hash algorithm.
func (h HashKey) HashAlgorithm() string {
	return ""
}

// BUG(eadmund): rather than returning the first stored hash, return
// the 'best' for some value of.
func (h HashKey) Subject() (sexprs.Sexp, error) {
	if h.Hashes == nil || len(h.Hashes) == 0 {
		return nil, fmt.Errorf("HashKey/ToSubject: No hash found")
	}
	return h.Hashes[0].Sexp(), nil
}

func (h HashKey) Equal(k Key) bool {
	if k == nil {
		return false
	}
	for _, hash1 := range h.Hashes {
		// can never return an error because we know algorithm is good
		hash2, _ := k.HashExp(hash1.Algorithm)
		if hash1.Equal(hash2) {
			return true
		}
	}
	return false
}