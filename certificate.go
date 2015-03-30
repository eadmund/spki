package spki

import (
	"github.com/eadmund/sexprs"
)

type Cert interface {
	Sexp() sexprs.Sexp
	String() string
	// above same as Sexp
	Certificate() sexprs.Sexp
	SequenceElement() sexprs.Sexp // every Certificate must be a SequenceElement
}

