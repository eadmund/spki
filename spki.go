package spki

import (
	"github.com/eadmund/sexprs"
	"bytes"
	"hash"
	"crypto/sha256"
	"crypto/sha512"
//	"fmt"
)

type Hash struct {
	Algorithm string
	Hash []byte
}

func (h Hash) Sexp() sexprs.Sexp {
	l := sexprs.List{sexprs.Atom{nil, []byte("hash")},
		sexprs.Atom{nil, []byte(h.Algorithm)},
		sexprs.Atom{nil, h.Hash}}
	return l
}

func (h Hash) String() string {
	return h.Sexp().String()
}

func (a Hash) Equal(b Hash) bool {
	return a.Algorithm == b.Algorithm && bytes.Equal(a.Hash, b.Hash)
}

var (
	HashAtom = sexprs.Atom{nil, []byte("hash")}
	KnownHashes = make(map[string]func () hash.Hash)
)

func EvalHash(s sexprs.Sexp) (h Hash, err error) {
	// FIXME: ignores optional URIs
	switch s := s.(type) {
	case sexprs.List:
		if HashAtom.Equal(s[0]) && len(s) >= 3 {
			algorithm, alg_ok := s[1].(sexprs.Atom)
			value, val_ok := s[2].(sexprs.Atom)
			if alg_ok && val_ok && validHash(algorithm.Value) {
				return Hash{string(algorithm.Value), 
					value.Value}, nil
			}
		}
	}
	return Hash{}, nil
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