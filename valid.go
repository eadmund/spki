package spki

import (
	"time"
	"github.com/eadmund/sexprs"
)

var (
	// SPKI v0 uses a non-ISO date representation.
	V0DateFmt = "2006-01-02_15:04:00"
)

// If times were represented as simple strings, then all the fancy
// comparisons could be reduced to string comparisons and the code
// would be simpler, albeit user code might need to do more
// conversion.

// A Valid represents certificate validity.  A nil NotBefore
// represents an infinitely-early beginning; a nil NotAfter represents
// an infinitely-late end.
type Valid struct {
	NotBefore, NotAfter *time.Time
}

func (v Valid) Intersect(v2 Valid) (nonEmpty bool, i Valid) {
	// i.NotBefore = max(v.NotBefore, v2.NotBefore)
	switch {
	case v.NotBefore == nil && v2.NotBefore == nil:
		i.NotBefore = nil
	case v.NotBefore == nil:
		i.NotBefore = v2.NotBefore
	case v2.NotBefore == nil:
		i.NotBefore = v.NotBefore
	case v.NotBefore.Before(*v2.NotBefore):
		i.NotBefore = v2.NotBefore
	default:
		i.NotBefore = v.NotBefore
	}
	// i.NotAfter = min(v.NotAfter, v2.NotAfter)
	switch {
	case v.NotAfter == nil && v2.NotAfter == nil:
		i.NotAfter = nil
	case v.NotAfter == nil:
		i.NotAfter = v2.NotAfter
	case v2.NotAfter == nil:
		i.NotAfter = v.NotAfter
	case v.NotAfter.After(*v2.NotAfter):
		i.NotAfter = v2.NotAfter
	default:
		i.NotAfter = v.NotAfter
	}
	// if NotBefore comes after NotAfter, it's an empty validity interval
	if i.NotBefore != nil && i.NotAfter != nil && i.NotBefore.After(*i.NotAfter) {
		return false, Valid{nil, nil}
	}
	return true, i
}

func (v Valid) Sexp() sexprs.Sexp {
	var notBefore, notAfter sexprs.Sexp
	if v.NotBefore != nil {
		notBefore = sexprs.List{sexprs.Atom{Value: []byte("not-before")}, sexprs.Atom{Value: []byte(v.NotBefore.Format(V0DateFmt))}}
	}
	if v.NotAfter != nil {
		notAfter = sexprs.List{sexprs.Atom{Value: []byte("not-after")}, sexprs.Atom{Value: []byte(v.NotAfter.Format(V0DateFmt))}}
	}
	if notBefore == nil && notAfter == nil {
		return nil
	}
	return sexprs.List{sexprs.Atom{Value: []byte("valid")}, notBefore, notAfter}
}

func (v Valid) String() string {
	return v.Sexp().String()
}