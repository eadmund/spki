package spki

import (
	"github.com/eadmund/sexprs"
)

type AuthCert struct {
	Expr sexprs.Sexp // the originally-parsed S-expression, for hashing
	Issuer Name
	Subject Subject
	Delegate bool
	Valid *Valid
	Tag sexprs.Sexp
}

func (a *AuthCert) Certificate() sexprs.Sexp {
	return a.Sexp()
}

func (a *AuthCert) Sexp() sexprs.Sexp {
	switch {
	case a == nil:
		return nil
	case a.Expr != nil:
		return a.Expr
	}
	var ds, vs sexprs.Sexp
	var s sexprs.List
	if a.Delegate {
		ds = sexprs.List{sexprs.Atom{Value: []byte("delegate")}}
	}
	if a.Valid != nil {
		vs = a.Valid.Sexp()
	}
	s = sexprs.List{sexprs.Atom{Value: []byte("cert")},
		sexprs.List{sexprs.Atom{Value: []byte("issuer")}, a.Issuer.Sexp()},
		sexprs.List{sexprs.Atom{Value: []byte("subject")}, a.Subject.Subject()}}
	if ds != nil {
		s = append(s, ds)
	}
	s = append(s, a.Tag)
	if vs != nil {
		s = append(s, vs)
	}
	return s
}