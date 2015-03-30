// Copyright 2013 Robert A. Uhl.  All rights reserved.
// Use of this source code is governed by an MIT-style license which may
// be found in the LICENSE file.

package spki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/eadmund/sexprs"
)

type PrivateKey struct {
	HashKey
	ecdsa.PrivateKey
}

// Sexp returns a well-formed S-expression for k
func (k *PrivateKey) Sexp() (s sexprs.Sexp) {
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

func (k *PrivateKey) Pack() []byte {
	return k.Sexp().Pack()
}

// Key-specific methods

// IsHash always returns false for a private key.
func (k *PrivateKey) IsHash() bool {
	return false
}


// PublicKey returns the public key associated with k.
func (k *PrivateKey) PublicKey() *PublicKey {
	if k == nil {
		return nil
	}
	p := new(PublicKey)
	p.Pk.Curve = k.Curve
	p.Pk.X = k.X
	p.Pk.Y = k.Y
	return p
}

func (k *PrivateKey) HashExp(algorithm string) (hash Hash, err error) {
	hash, err = k.HashKey.HashExp(algorithm)
	if err != nil {
		return hash, err
	}
	newHash, ok := KnownHashes[algorithm]
	if !ok {
		return hash, fmt.Errorf("Unknown hash algorithm %s", algorithm)
	}
	hasher := newHash()
	_, err = hasher.Write(k.PublicKey().Pack())
	if err != nil {
		return hash, err
	}
	hash.Algorithm = algorithm
	hash.Hash = hasher.Sum(nil)
	return hash, nil
}

func (k *PrivateKey) Hashed(algorithm string) ([]byte, error) {
	hash, err := k.HashExp(algorithm)
	return hash.Hash, err
}

func (k *PrivateKey) SignatureAlgorithm() string {
	return "ecdsa-sha2"
}

func (k *PrivateKey) HashAlgorithm() string {
	return "sha2"
}

func (k *PrivateKey) Equal(k2 Key) bool {
	if k2 == nil {
		return false
	}
	for algorithm, _ := range KnownHashes {
		// we know that HashExp cannot fail because the algorithms will be correct
		hash1, _ := k.HashExp(algorithm)
		hash2, _ := k2.HashExp(algorithm)
		if hash1.Equal(hash2) {
			return true
		}
	}
	return false
}

func (k *PrivateKey) Subject() (sexp sexprs.Sexp) {
	var algorithm string
	switch k.Curve {
	case elliptic.P256():
		algorithm = "sha256"
	case elliptic.P384():
		algorithm = "sha384"
	default:
		return nil
	}
	hash, err := k.HashExp(algorithm)
	if err != nil {
		return nil
	}
	return hash.Subject()
}

func (k *PrivateKey) sign(h Hash) (sig *Signature, err error) {
	r, s, err := ecdsa.Sign(rand.Reader, &k.PrivateKey, h.Hash)
	if err != nil {
		return nil, err
	}
	return &Signature{Hash: h, Principal: k.PublicKey(), R: r, S: s}, nil
}

func (k *PrivateKey) Sign(s sexprs.Sexp) (sig *Signature, err error) {
	hash := Hash{}
	switch k.Curve {
	case elliptic.P256():
		hash.Algorithm = "sha256"
	case elliptic.P384():
		hash.Algorithm = "sha384"
	default:
		return nil, fmt.Errorf("Only p256 & p384 are currently supported")
	}
	hasher := KnownHashes[hash.Algorithm]()
	_, err = hasher.Write(s.Pack())
	if err != nil {
		return nil, err
	}
	hash.Hash = hasher.Sum(nil)
	return k.sign(hash)
}

// String is a shortcut for k.Sexp().String()
func (k *PrivateKey) String() (s string) {
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

// BUG(eadmund): parse algorithm as a canonical s-expression

// GeneratePrivateKey generates a new private key as specified by
// algorithm, e.g. "(ecdsa-sha2 (curve p256))".  Returns an error if the
// algorithm is unknown.
func GeneratePrivateKey(algorithm string) (k *PrivateKey, err error) {
	switch algorithm {
	case "(ecdsa-sha2 (curve p256))":
		return GenerateP256Key()
	default:
		return nil, fmt.Errorf("Unknown algorithm '%s'", algorithm)
	}
}

func GenerateP256Key() (k *PrivateKey, err error) {
	kk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	// BUG(eadmund): zeroise kk afterwards
	k = &PrivateKey{HashKey{}, *kk}
	return k, nil
}

func (k *PrivateKey) IssueAuthCert(publicKey *PublicKey, tag sexprs.Sexp, validity Valid) (c AuthCert) {
	c.Issuer = Name{Principal: k.PublicKey()}
	c.Subject = publicKey
	c.Delegate = true
	c.Valid = &Valid{}
	*c.Valid = validity
	c.Tag = tag
	return
}
