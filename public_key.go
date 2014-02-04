// Copyright 2013 Robert A. Uhl.  All rights reserved.
// Use of this source code is governed by an MIT-style license which may
// be found in the LICENSE file.

package spki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"github.com/eadmund/sexprs"
)

type PublicKey struct {
	HashKey
	ecdsa.PublicKey
}

// EvalPublicKey converts the S-expression s to a PublicKey, or returns
// an error.  The format of a 256-bit ECDSA public key is:
//    (public-key (ecdsa-sha2 (curve p256) (x |...|) (y |...|)))
// The format of a 384-bit ECDSA public key is:
//    (public-key (ecdsa-sha2 (curve p384) (x |...|) (y |...|)))
// Neither RSA, DSA, NIST curves other than p256 & p384 nor non-NIST-curve 
// ECDSA keys are supported at this point in time.  In the future PublicKey
// will likely be an interface.
func EvalPublicKey(s sexprs.Sexp) (k *PublicKey, err error) {
	l, ok := s.(sexprs.List)
	if !ok {
		return nil, fmt.Errorf("Key S-expression must be a list")
	}
	if !publicKeyAtom.Equal(l[0]) {
		return nil, fmt.Errorf("Key S-expression must start with 'public-key'")
	}
	if len(l) != 2 {
		return nil, fmt.Errorf("Key S-expression must have two elements")
	}
	return evalECDSAPublicKey(l[1])
}

func evalECDSAPublicKey(s sexprs.Sexp) (k *PublicKey, err error) {
	l, ok := s.(sexprs.List)
	if !ok {
		return nil, fmt.Errorf("ECDSA key S-expression must be a list")
	}
	if len(l) != 4 {
		return nil, fmt.Errorf("ECDSA key must have 4 elements")
	}
	switch {
	case ecdsa256Atom.Equal(l[0]):
		k, err = evalECDSA256PublicKeyTerms(l)
		if err != nil {
			return nil, err
		}
		return k, nil
	case ecdsa384Atom.Equal(l[0]):
		panic("p384 not yet supported")
	default:
		return nil, fmt.Errorf("ECDSA key S-expression must start with 'ecdsa-sha2'")
	}
	panic("Can't reach here")
}

func evalECDSA256PublicKeyTerms(l sexprs.List) (k *PublicKey, err error) {
	k = new(PublicKey)
	curve, err := evalCurve(l[1])
	if err != nil {
		return nil, err
	}
	switch curve {
	case "p256":
		k.Curve = elliptic.P256()
	case "p384":
		k.Curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("Curve must be either 'p256' or 'p384'")
	}
	k.X, err = evalNamedBigInt("x", l[2])
	if err != nil {
		return nil, err
	}
	k.Y, err = evalNamedBigInt("y", l[3])
	if err != nil {
		return nil, err
	}
	return k, nil
}

func evalCurve(l sexprs.Sexp) (curve string, err error) {
	ll, ok := l.(sexprs.List)
	if !ok {
		return curve, fmt.Errorf("Curve must be a list")
	}
	if c, ok := ll[0].(sexprs.Atom); !ok || !bytes.Equal(c.Value, []byte("curve")) {
		return curve, fmt.Errorf("Curve must start with 'curve'")
	}
	if c, ok := ll[1].(sexprs.Atom); !ok {
		return curve, fmt.Errorf("Curve must be either p256 or p512")
	} else {
		curve = string(c.Value)
		if curve != "p256" && curve != "p512" {
			return curve, fmt.Errorf("Curve must be either p256 or p512")
		}
		return curve, nil
	}
	panic("Can't get here")
}

func (k *PublicKey) Sexp() (s sexprs.Sexp) {
	var curve sexprs.Atom
	switch k.Curve {
	case elliptic.P256():
		curve.Value = []byte("p256")
	case elliptic.P384():
		curve.Value = []byte("p384")
	default:
		panic(fmt.Sprintf("Bad curve value %v", k.Curve))
	}
	return sexprs.List{
		sexprs.Atom{Value: []byte("public-key")},
		sexprs.List{
			sexprs.Atom{Value: []byte("ecdsa-sha2")},
			sexprs.List{
				sexprs.Atom{Value: []byte("curve")},
				curve,
			},
			sexprs.List{
				sexprs.Atom{Value: []byte("x")},
				sexprs.Atom{Value: k.X.Bytes()},
			},
			sexprs.List{
				sexprs.Atom{Value: []byte("y")},
				sexprs.Atom{Value: k.Y.Bytes()},
			},
		},
	}
}

func (k *PublicKey) Pack() ([]byte) {
	return k.Sexp().Pack()
}

// Key methods

// IsHash always returns false for a public key.
func (k *PublicKey) IsHash() bool {
	return false
}

// PublicKey returns the key itself.
func (k *PublicKey) PublicKey() *PublicKey {
	return &k
}

func (k *PublicKey) HashedExpr(algorithm string) (hash Hash, err error) {
	hash, err = k.HashKey.HashedExpr(algorithm)
	if err != nil {
		return hash, nil
	}
	newHash, ok := KnownHashes[algorithm]
	if !ok {
		return hash, fmt.Errorf("Unknown hash algorithm %s", algorithm)
	}
	hasher := newHash()
	_, err = hasher.Write(k.Pack())
	if err != nil {
		return hash, err
	}
	hash.Algorithm = algorithm
	hash.Hash = hasher.Sum(nil)
	return hash, nil
}

func (k *PublicKey) Hashed(algorithm string) ([]byte, error) {
	hash, err := k.HashedExpr(algorithm)
	return hash.Hash, err
}

func (k *PublicKey) SignatureAlgorithm() string {
	return "ecdsa-sha2"
}

func (k *PublicKey) HashAlgorithm() string {
	switch k.Curve {
	case elliptic.P256():
		return "p256"
	case elliptic.P384():
		return "p384"
	default:
		return ""
	}
}
