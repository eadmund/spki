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

	// KnownHashes is a map of all known hashes to their hash
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

#### type URIs

```go
type URIs []*url.URL
```


#### func  EvalURIs

```go
func EvalURIs(s sexprs.Sexp) (u URIs, err error)
```
