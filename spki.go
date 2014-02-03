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
	"fmt"
	"github.com/eadmund/sexprs"
	"math/big"
	"net/url"
)

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

func evalNamedBigInt(name string, s sexprs.Sexp) (n *big.Int, err error) {
	l, ok := s.(sexprs.List)
	if !ok || len(l) != 2 {
		return nil, fmt.Errorf("Named big integer term must be a list (%s OCTET-STRING)", name)
	}
	first, ok := l[0].(sexprs.Atom)
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