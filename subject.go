// Copyright 2014 Robert A. Uhl.  All rights reserved.
// Use of this source code is governed by an MIT-style license which may
// be found in the LICENSE file.

package spki

import (
	"github.com/eadmund/sexprs"
)

type Subject interface {
	sexprs.Sexp
	// SubjectSexp returns an S-expression suitable for use as a
	// subject object of a certificate, e.g. the hash expression
	// in "(subject(hash sha256
	// |5v5x48LHmVtW1du0iMqdgK+v6/oybSBU/NCYne0XCMw=|))".
	SubjectSexp() Sexp
}