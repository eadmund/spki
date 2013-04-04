# spki
--
    import "github.com/eadmund/spki"

Package spki implements the Simple Public Key Infrastructure
documented in RFCs 2692, 2693 and in various related Internet
drafts.  SPKI is a superior—albeit little-used—alternative to the
X.509 certificate standard ubiquitous across the Internet.  Among
its advantages are a clearer & more practical trust model and a
rather more human-readable certificate format.

I'm indebted to Inferno's spki(2), whose API I have deliberately,
mimicked, making it more Go-like as seemed meet.

## Usage

```go
var (

	// KnownHashes is a map of all known hash names to the associated hash
	// constructors.
	KnownHashes = make(map[string]func() hash.Hash)
)
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

#### type PrivateKey

```go
type PrivateKey struct {
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

#### func (PrivateKey) PublicKey

```go
func (k PrivateKey) PublicKey() *PublicKey
```
PublicKey returns the public key associated with k

#### func (PrivateKey) Sexp

```go
func (k PrivateKey) Sexp() (s sexprs.Sexp)
```
Sexp returns a well-formed S-expression for k

#### func (*PrivateKey) Sign

```go
func (k *PrivateKey) Sign(s sexprs.Sexp) (sig *Signature, err error)
```

#### func (PrivateKey) String

```go
func (k PrivateKey) String() (s string)
```
String is a shortcut for k.Sexp().String()

#### type PublicKey

```go
type PublicKey struct {
	ecdsa.PublicKey
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

Neither RSA, DSA, NIST curves other than p256 & p34 nor non-NIST-curve ECDSA
keys are supported at this point in time. In the future PublicKey will likely be
an interface.

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

#### type URIs

```go
type URIs []*url.URL
```


#### func  EvalURIs

```go
func EvalURIs(s sexprs.Sexp) (u URIs, err error)
```
