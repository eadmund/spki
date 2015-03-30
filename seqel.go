package spki

import (
	"github.com/eadmund/sexprs"
)

type SequenceElement interface {
	// Really, this is just the same as sexprs.Sexp; it's used to
	// indicate that a slice of SequenceElements is intended to
	// actually be a sequence
	Sexp() sexprs.Sexp
	String() string
}

type Sequence []SequenceElement

func (seq Sequence) Sexp() sexprs.Sexp {
	s := sexprs.List{sexprs.Atom{Value: []byte("sequence")}}
	for _, elt := range seq {
		s = append(s, elt.Sexp())
	}
	return s
}

func (seq Sequence) String() string {
	return seq.Sexp().String()
}
