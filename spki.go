// Copyright 2013 Robert A. Uhl.  All rights reserved.
// Use of this source code is governed by an MIT-style license which may
// be found in the LICENSE file.

// Package spki implements the Simple Public Key Infrastructure
// documented in RFCs 2692, 2693 and in various related Internet
// drafts.  SPKI is a superior—albeit little-used—alternative to the
// X.509 certificate standard ubiquitous across the Internet.  Among
// its advantages are a clearer & more practical trust model and a
// rather more human-readable certificate format.
//
// I'm indebted to Inferno's spki(2), whose API I have deliberately,
// mimicked, making it more Go-like as seemed meet.
package spki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/eadmund/sexprs"
	"hash"
	"math/big"
	"net/url"
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
	urisAtom      = sexprs.Atom{nil, []byte("uris")}
	publicKeyAtom = sexprs.Atom{nil, []byte("public-key")}
	privateKeyAtom = sexprs.Atom{nil, []byte("private-key")}
	ecdsa256Atom  = sexprs.Atom{nil, []byte("ecdsa-sha2")}
	ecdsa384Atom  = sexprs.Atom{nil, []byte("ecdsa-sha2")}
	// KnownHashes is a map of all known hashes to their hash
	// constructors.
	KnownHashes = make(map[string]func() hash.Hash)
)

// EvalHash converts a hash S-expression to its equivalent Hash struct.
func EvalHash(s sexprs.Sexp) (h Hash, err error) {
	// FIXME: ignores optional URIs
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

type URIs []*url.URL

func EvalURIs(s sexprs.Sexp) (u URIs, err error) {
	switch s := s.(type) {
	case sexprs.List:
		if len(s) > 1 && urisAtom.Equal(s[0]) {
			u = make(URIs, len(s)-1)
			for i := range u {
				switch uri := s[i+1].(type) {
				case sexprs.Atom:
					u[i], err = url.Parse(string(uri.Value))
					if err != nil {
						return nil, err
					}
				default:
					return nil, fmt.Errorf("URI expected")
				}
			}
			return u, nil
		}
	default:
		return nil, fmt.Errorf("S-expression not a list")
	}
	panic("Can't reach here")
}

type PrivateKey struct {
	ecdsa.PrivateKey
}

func (k PrivateKey) Sexp() (s sexprs.Sexp) {
	l := make(sexprs.List, 2)
	l[0] = sexprs.Atom{Value: []byte("private-key")}
	ll := make(sexprs.List, 5)
	l[1] = ll
	ll[0] = sexprs.Atom{Value: []byte("ecdsa-sha2")}
	c := make(sexprs.List, 2)
	ll[1] = c
	c[0] = sexprs.Atom{Value: []byte("curve")}
	switch k.Curve {
	case elliptic.P256():
		c[1] = sexprs.Atom{Value: []byte("p256")}
	case elliptic.P384():
		c[1] = sexprs.Atom{Value: []byte("p384")}
	default:
		return nil
	}
	x := make(sexprs.List, 2)
	ll[2] = x
	x[0] = sexprs.Atom{Value: []byte("x")}
	x[1] = sexprs.Atom{Value: k.X.Bytes()}
	y := make(sexprs.List, 2)
	ll[3] = y
	y[0] = sexprs.Atom{Value: []byte("y")}
	y[1] = sexprs.Atom{Value: k.Y.Bytes()}
	d := make(sexprs.List, 2)
	ll[4] = d
	d[0] = sexprs.Atom{Value: []byte("d")}
	d[1] = sexprs.Atom{Value: k.D.Bytes()}
	return l
}

func (k PrivateKey) String() (s string) {
	return k.Sexp().String()
}

// EvalPrivateKey converts the S-expression s to a PrivateKey, or
// returns an err.  The format of a 256-bit ECDSA private key is:
//    (private-key (ecdsa-sha2 (curve p256) (x |...|) (y |...|) (d |...|)))
// The format of a 384-bit ECDSA private key is:
//    (private-key (ecdsa-sha2 (curve p384) (x |...|) (y |...|) (d |...|)))
// Neither RSA, DSA, NIST curves other than p256 & p34 nor non-NIST-curve 
// ECDSA keys are supported at this point in time.  In the future PrivateKey
// will likely be an interface.
func EvalPrivateKey(s sexprs.Sexp) (k PrivateKey, err error) {
	l, ok := s.(sexprs.List)
	if !ok {
		return k, fmt.Errorf("Key S-expression must be a list")
	}
	if !privateKeyAtom.Equal(l[0]) {
		return k, fmt.Errorf("Key S-expression must start with 'private-key'")
	}
	if len(l) != 2 {
		return k, fmt.Errorf("Key S-expression must have two elements")
	}
	return evalECDSAPrivateKey(l[1])
	panic("Can't reach here")
}

func evalECDSAPrivateKey(s sexprs.Sexp) (k PrivateKey, err error) {
	l, ok := s.(sexprs.List)
	if !ok {
		return k, fmt.Errorf("ECDSA key S-expression must be a list")
	}
	if len(l) != 5 {
		return k, fmt.Errorf("ECDSA key must have 5 elements")
	}
	switch {
	case ecdsa256Atom.Equal(l[0]):
		k, err = evalECDSASHA2PrivateKeyTerms(l)
		if err != nil {
			return k, err
		}
		return k, nil
	case ecdsa384Atom.Equal(l[0]):
	default:
		return k, fmt.Errorf("ECDSA key S-expression must start with 'ecdsa-sha2'")
	}
	panic("Can't reach here")
}

func evalECDSASHA2PrivateKeyTerms(l sexprs.List) (k PrivateKey, err error) {
	curve, err := evalCurve(l[1])
	if err != nil {
		return k, err
	}
	switch curve {
	case "p256":
		k.Curve = elliptic.P256()
	case "p384":
		k.Curve = elliptic.P384()
	default:
		return k, fmt.Errorf("Curve must be either 'p256' or 'p384'")
	}
	k.X, err = evalNamedBigInt("x", l[2])
	if err != nil {
		return k, err
	}
	k.Y, err = evalNamedBigInt("y", l[3])
	if err != nil {
		return k, err
	}
	k.D, err = evalNamedBigInt("d", l[4])
	if err != nil {
		return k, err
	}
	return k, nil
}

type PublicKey struct {
	Key ecdsa.PublicKey
}

// EvalPublicKey converts the S-expression s to a PublicKey, or returns
// an error.  The format of a 256-bit ECDSA public key is:
//    (public-key (ecdsa-sha2 (curve p256) (x |...|) (y |...|)))
// The format of a 384-bit ECDSA public key is:
//    (public-key (ecdsa-sha2 (curve p384) (x |...|) (y |...|)))
// Neither RSA, DSA, NIST curves other than p256 & p34 nor non-NIST-curve 
// ECDSA keys are supported at this point in time.  In the future PublicKey
// will likely be an interface.
func EvalPublicKey(s sexprs.Sexp) (k PublicKey, err error) {
	l, ok := s.(sexprs.List)
	if !ok {
		return k, fmt.Errorf("Key S-expression must be a list")
	}
	if !publicKeyAtom.Equal(l[0]) {
		return k, fmt.Errorf("Key S-expression must start with 'public-key'")
	}
	if len(l) != 2 {
		return k, fmt.Errorf("Key S-expression must have two elements")
	}
	return evalECDSAPublicKey(l[1])
	panic("Can't reach here")
}

func evalECDSAPublicKey(s sexprs.Sexp) (k PublicKey, err error) {
	l, ok := s.(sexprs.List)
	if !ok {
		return k, fmt.Errorf("ECDSA key S-expression must be a list")
	}
	if len(l) != 4 {
		return k, fmt.Errorf("ECDSA key must have 4 elements")
	}
	switch {
	case ecdsa256Atom.Equal(l[0]):
		k.Key, err = evalECDSA256PublicKeyTerms(l)
		if err != nil {
			return k, err
		}
		return k, nil
	case ecdsa384Atom.Equal(l[0]):
	default:
		return k, fmt.Errorf("ECDSA key S-expression must start with 'ecdsa-sha2'")
	}
	panic("Can't reach here")
}

func evalECDSA256PublicKeyTerms(l sexprs.List) (k ecdsa.PublicKey, err error) {
	curve, err := evalCurve(l[1])
	if err != nil {
		return k, err
	}
	switch curve {
	case "p256":
		k.Curve = elliptic.P256()
	case "p384":
		k.Curve = elliptic.P384()
	default:
		return k, fmt.Errorf("Curve must be either 'p256' or 'p384'")
	}
	k.X, err = evalNamedBigInt("x", l[2])
	if err != nil {
		return k, err
	}
	k.Y, err = evalNamedBigInt("y", l[3])
	if err != nil {
		return k, err
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

func evalNamedBigInt(name string, s sexprs.Sexp) (n *big.Int, err error) {
	l, ok := s.(sexprs.List)
	if !ok || len(l) != 2 {
		return nil, fmt.Errorf("Named big integer term must be a list (%s OCTET-STRING)", name)
	}
	first, ok := l[0].(sexprs.Atom);
	if !ok || !bytes.Equal(first.Value, []byte(name)) {
		return nil, fmt.Errorf("Expected term name %s %v %v", name, ok, first)
	}
	if raw, ok := l[1].(sexprs.Atom); !ok {
		return nil, fmt.Errorf("Value in (%s VALUE) must be an atom", name)
	} else {
		n = big.NewInt(0).SetBytes(raw.Value)
		return n, nil
	}
	panic("Can't get here")
}
