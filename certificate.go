package spki

import (
	"github.com/eadmund/sexprs"
)

type Cert interface {
	Sexp() sexprs.Sexp
	String() string
	// Same as Sexp
	Certificate() sexprs.Sexp
}

