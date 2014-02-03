// Copyright 2014 Robert A. Uhl.  All rights reserved.
// Use of this source code is governed by an MIT-style license which may
// be found in the LICENSE file.

package spki

import (
	"github.com/eadmund/sexprs"
)

type Subject interface {
	sexprs.Sexp
}
