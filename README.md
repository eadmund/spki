# spki
--
    import "github.com/eadmund/spki"

Package spki implements the Simple Public Key Infrastructure
documented in RFCs 2692, 2693 and in various related Internet
drafts.  SPKI is a superior—albeit little-used—alternative to the
X.509 certificate standard ubiquitous across the Internet.  Among
its advantages are a clearer & more practical trust model and a
rather more human-readable certificate format.

I'm indebted to Inferno's spki(2), whose API I have deliberately
mimicked, making it more Go-like as seemed meet.

## Usage

```go
var (

	// KnownHashes is a map of all known hash names to the associated hash
	// constructors.
	KnownHashes = make(map[string]func() hash.Hash)
)
```

```go
var (
	// SPKI v0 uses a non-ISO date representation.
	V0DateFmt = "2006-01-02_15:04:00"
)
```

#### type AuthCert

```go
type AuthCert struct {
	Expr     sexprs.Sexp // the originally-parsed S-expression, for hashing
	Issuer   Name
	Subject  Subject
	Delegate bool
	Valid    *Valid
	Tag      sexprs.Sexp
}
```


#### func (AuthCert) Certificate

```go
func (a AuthCert) Certificate() sexprs.Sexp
```

#### func (AuthCert) Sexp

```go
func (a AuthCert) Sexp() sexprs.Sexp
```

#### func (AuthCert) String

```go
func (a AuthCert) String() string
```

#### type Cert

```go
type Cert interface {
	Sexp() sexprs.Sexp
	String() string
	// above same as Sexp
	Certificate() sexprs.Sexp
	SequenceElement() sexprs.Sexp // every Certificate must be a SequenceElement
}
```


#### type Hash

```go
type Hash struct {
	Algorithm string // sha224, sha256, sha384 or sha512
	Hash      []byte // a byte slice of the appropriate length
	URIs      URIs   // zero or more associated URIs
}
```

A Hash represents the Hash of some value under Algorithm. It may optionally have
an array of associated URIs which may be used to help retrieve the hashed
object. Although the SPKI standard calls these URIs, they really are URLs, as
they would be used to locate, not just indicate, the hashed object.

#### func  EvalHash

```go
func EvalHash(s sexprs.Sexp) (h Hash, err error)
```
EvalHash converts a hash S-expression to its equivalent Hash struct.

#### func (Hash) Equal

```go
func (a Hash) Equal(b Hash) bool
```
Equal returns true if a & b are equivalent hash values, i.e. if they share the
same Algorithm and the same Hash. It ignores the optional URIs.

#### func (Hash) Sexp

```go
func (h Hash) Sexp() (s sexprs.Sexp)
```
Sexp returns an S-expression representing the Hash h. Calling s.Pack() will
return h's canonical S-expression form.

#### func (Hash) String

```go
func (h Hash) String() string
```
String returns h's advanced S-expression form.

#### func (Hash) Subject

```go
func (h Hash) Subject() sexprs.Sexp
```
A Hash may be used as the subject of a certificate

#### type HashKey

```go
type HashKey struct {
	Hashes []Hash
}
```

A HashKey is just the hash value(s) of a key, without any public or private
component; as such, it can only report its value under its own algorithm(s), and
cannot be used to sign or verify anything.

#### func (HashKey) Equal

```go
func (h HashKey) Equal(k Key) bool
```

#### func (HashKey) HashAlgorithm

```go
func (h HashKey) HashAlgorithm() string
```
Hashed keys never have any known hash algorithm.

#### func (HashKey) HashExp

```go
func (h HashKey) HashExp(algorithm string) (hh Hash, err error)
```

#### func (HashKey) Hashed

```go
func (h HashKey) Hashed(algorithm string) ([]byte, error)
```

#### func (HashKey) IsHash

```go
func (h HashKey) IsHash() bool
```

#### func (HashKey) PublicKey

```go
func (h HashKey) PublicKey() *PublicKey
```

#### func (HashKey) SignatureAlgorithm

```go
func (h HashKey) SignatureAlgorithm() string
```
Hashed keys never have any known signature algorithm.

#### func (HashKey) String

```go
func (h HashKey) String() string
```

#### func (HashKey) Subject

```go
func (h HashKey) Subject() sexprs.Sexp
```
BUG(eadmund): rather than returning the first stored hash, return the 'best' for
some value of.

#### type HashNotFoundError

```go
type HashNotFoundError struct {
	Hash Hash
}
```


#### func (HashNotFoundError) Error

```go
func (h HashNotFoundError) Error() string
```

#### type Key

```go
type Key interface {
	// Returns true if the key is just a hash.
	IsHash() bool
	// Returns the public key for the key: the key itself, if it's
	// already a public key; a public version of the key, if it's
	// a private key; or nil, if it is a hash without a key.
	PublicKey() *PublicKey
	// Returns the hash value of the key under a particular
	// algorithm, or an error if the key is just a hash and the
	// specified algorithm is not the algorithm used to generate
	// it.
	Hashed(algorithm string) ([]byte, error)
	// Returns the hash value of the key as per Hashed, but as a
	// Hash object.
	HashExp(algorithm string) (Hash, error)
	// Returns the SPKI signature algorithm of the key,
	// e.g. "ecdsa-sha256".  May be the empty string if unknown.
	SignatureAlgorithm() string
	// Returns the SPKI hash algorithm the key uses in signing,
	// e.g. "sha256".  May be the empty string if unknown.
	HashAlgorithm() string
	Equal(Key) bool
	Sexp() sexprs.Sexp
	String() string
}
```


#### type Name

```go
type Name struct {
	Principal Key
	Names     []string
}
```

A Name represents local & extended SPKI names, as well as simple principals
which are just a key. A local name will have one name in Names; an extended name
will have multiple names. A simple principal will have Principal but no Names.

#### func (*Name) Equal

```go
func (n *Name) Equal(n2 Name) bool
```

#### func (*Name) IsLocal

```go
func (n *Name) IsLocal() bool
```
IsLocal returns true if n is a local name—i.e., len(n.Names) is 0 or 1

#### func (*Name) IsPrefix

```go
func (n *Name) IsPrefix(n2 *Name) bool
```
IsPrefix returns true if n is a prefix of n2

#### func (*Name) IsPrincipal

```go
func (n *Name) IsPrincipal() bool
```
IsPrincipal returns true if n is a principal name, i.e. if it refers directly to
a key and no names in that key's namespace.

#### func (*Name) Local

```go
func (n *Name) Local() *Name
```
Local returns the local part of n, e.g. (name #123# a b c) would return (name
#123# a).

#### func (*Name) Sexp

```go
func (n *Name) Sexp() sexprs.Sexp
```

#### func (*Name) String

```go
func (n *Name) String() string
```

#### type PrivateKey

```go
type PrivateKey struct {
	HashKey
	ecdsa.PrivateKey
}
```


#### func  EvalPrivateKey

```go
func EvalPrivateKey(s sexprs.Sexp) (k PrivateKey, err error)
```
EvalPrivateKey converts the S-expression s to a PrivateKey, or returns an err.
The format of a 256-bit ECDSA private key is:

    (private-key (ecdsa-sha2 (curve p256) (x |...|) (y |...|) (d |...|)))

The format of a 384-bit ECDSA private key is:

    (private-key (ecdsa-sha2 (curve p384) (x |...|) (y |...|) (d |...|)))

Neither RSA, DSA, NIST curves other than p256 & p34 nor non-NIST-curve ECDSA
keys are supported at this point in time. In the future PrivateKey will likely
be an interface.

#### func  GenerateP256Key

```go
func GenerateP256Key() (k *PrivateKey, err error)
```

#### func  GeneratePrivateKey

```go
func GeneratePrivateKey(algorithm string) (k *PrivateKey, err error)
```
GeneratePrivateKey generates a new private key as specified by algorithm, e.g.
"(ecdsa-sha2 (curve p256))". Returns an error if the algorithm is unknown.

#### func (*PrivateKey) Equal

```go
func (k *PrivateKey) Equal(k2 Key) bool
```

#### func (*PrivateKey) HashAlgorithm

```go
func (k *PrivateKey) HashAlgorithm() string
```

#### func (*PrivateKey) HashExp

```go
func (k *PrivateKey) HashExp(algorithm string) (hash Hash, err error)
```

#### func (*PrivateKey) Hashed

```go
func (k *PrivateKey) Hashed(algorithm string) ([]byte, error)
```

#### func (*PrivateKey) IsHash

```go
func (k *PrivateKey) IsHash() bool
```
IsHash always returns false for a private key.

#### func (*PrivateKey) IssueAuthCert

```go
func (k *PrivateKey) IssueAuthCert(publicKey *PublicKey, tag sexprs.Sexp, validity Valid) (c AuthCert)
```

#### func (*PrivateKey) Pack

```go
func (k *PrivateKey) Pack() []byte
```

#### func (*PrivateKey) PublicKey

```go
func (k *PrivateKey) PublicKey() *PublicKey
```
PublicKey returns the public key associated with k.

#### func (*PrivateKey) Sexp

```go
func (k *PrivateKey) Sexp() (s sexprs.Sexp)
```
Sexp returns a well-formed S-expression for k

#### func (*PrivateKey) Sign

```go
func (k *PrivateKey) Sign(s sexprs.Sexp) (sig *Signature, err error)
```

#### func (*PrivateKey) SignatureAlgorithm

```go
func (k *PrivateKey) SignatureAlgorithm() string
```

#### func (*PrivateKey) String

```go
func (k *PrivateKey) String() (s string)
```
String is a shortcut for k.Sexp().String()

#### func (*PrivateKey) Subject

```go
func (k *PrivateKey) Subject() (sexp sexprs.Sexp)
```

#### type PublicKey

```go
type PublicKey struct {
	HashKey
	Pk ecdsa.PublicKey
}
```


#### func  EvalPublicKey

```go
func EvalPublicKey(s sexprs.Sexp) (k *PublicKey, err error)
```
EvalPublicKey converts the S-expression s to a PublicKey, or returns an error.
The format of a 256-bit ECDSA public key is:

    (public-key (ecdsa-sha2 (curve p256) (x |...|) (y |...|)))

The format of a 384-bit ECDSA public key is:

    (public-key (ecdsa-sha2 (curve p384) (x |...|) (y |...|)))

Neither RSA, DSA, NIST curves other than p256 & p384 nor non-NIST-curve ECDSA
keys are supported at this point in time. In the future PublicKey will likely be
an interface.

#### func (*PublicKey) Equal

```go
func (k *PublicKey) Equal(k2 Key) bool
```

#### func (*PublicKey) HashAlgorithm

```go
func (k *PublicKey) HashAlgorithm() string
```

#### func (*PublicKey) HashExp

```go
func (k *PublicKey) HashExp(algorithm string) (hash Hash, err error)
```

#### func (*PublicKey) Hashed

```go
func (k *PublicKey) Hashed(algorithm string) ([]byte, error)
```

#### func (*PublicKey) IsHash

```go
func (k *PublicKey) IsHash() bool
```
IsHash always returns false for a public key.

#### func (*PublicKey) Pack

```go
func (k *PublicKey) Pack() []byte
```

#### func (*PublicKey) PublicKey

```go
func (k *PublicKey) PublicKey() *PublicKey
```
PublicKey returns the key itself.

#### func (*PublicKey) Sexp

```go
func (k *PublicKey) Sexp() (s sexprs.Sexp)
```

#### func (*PublicKey) SignatureAlgorithm

```go
func (k *PublicKey) SignatureAlgorithm() string
```

#### func (*PublicKey) String

```go
func (k *PublicKey) String() string
```

#### func (*PublicKey) Subject

```go
func (k *PublicKey) Subject() sexprs.Sexp
```
Subject always returns the 'natural' hash of k, i.e. a hash with an appropriate
length.

#### type Sequence

```go
type Sequence []SequenceElement
```


#### func (Sequence) Sexp

```go
func (seq Sequence) Sexp() sexprs.Sexp
```

#### func (Sequence) String

```go
func (seq Sequence) String() string
```

#### type SequenceElement

```go
type SequenceElement interface {
	// Really, this is just the same as sexprs.Sexp; it's used to
	// indicate that a slice of SequenceElements is intended to
	// actually be a sequence
	Sexp() sexprs.Sexp
	String() string
}
```


#### type Signature

```go
type Signature struct {
	Hash      Hash
	Principal *PublicKey
	R, S      *big.Int
}
```

Signature represents an ECDSA signature. Neither DSA nor RSA are currently
supported. Should RSA be supported, expect Signature to become an interface.

#### func  EvalSignature

```go
func EvalSignature(s sexprs.Sexp, lookupFunc func(Hash) *PublicKey) (sig *Signature, err error)
```
EvalSignature converts a signature S-expression to a Signature. An ECDSA
signature looks like:

    (signature (hash sha256 |...|) PRINCIPAL (ecdsa |...| |...|))

where PRINCIPAL is either a public key or the hash of a public key. If PRINCIPAL
is a hash, lookupFunc is used to look it up; if it is nil or returns nil, then
EvalSignature returns a HashNotFoundError.

#### func (*Signature) Sexp

```go
func (sig *Signature) Sexp() sexprs.Sexp
```
Sexp returns an S-expression fully representing sig

#### func (*Signature) String

```go
func (sig *Signature) String() string
```
String is a shortcut for sig.Sexp().String()

#### type Subject

```go
type Subject interface {
	// SubjectSexp returns an S-expression suitable for use as a
	// subject object of a certificate, e.g. the hash expression
	// in "(subject (hash sha256
	// |5v5x48LHmVtW1du0iMqdgK+v6/oybSBU/NCYne0XCMw=|))".
	Subject() sexprs.Sexp
}
```


#### type URIs

```go
type URIs []*url.URL
```


#### func  EvalURIs

```go
func EvalURIs(s sexprs.Sexp) (u URIs, err error)
```

#### type Valid

```go
type Valid struct {
	NotBefore, NotAfter *time.Time
}
```

A Valid represents certificate validity. A nil NotBefore represents an
infinitely-early beginning; a nil NotAfter represents an infinitely-late end.

#### func (Valid) Intersect

```go
func (v Valid) Intersect(v2 Valid) (nonEmpty bool, i Valid)
```

#### func (Valid) Sexp

```go
func (v Valid) Sexp() sexprs.Sexp
```

#### func (Valid) String

```go
func (v Valid) String() string
```
