# spki
--
    import "github.com/eadmund/spki"


## Usage

```go
var (
	HashAtom    = sexprs.Atom{nil, []byte("hash")}
	KnownHashes = make(map[string]func() hash.Hash)
)
```

#### type Hash

```go
type Hash struct {
	Algorithm string
	Hash      []byte
	URIs      []url.URL
}
```


#### func  EvalHash

```go
func EvalHash(s sexprs.Sexp) (h Hash, err error)
```

#### func (Hash) Equal

```go
func (a Hash) Equal(b Hash) bool
```

#### func (Hash) Sexp

```go
func (h Hash) Sexp() sexprs.Sexp
```

#### func (Hash) String

```go
func (h Hash) String() string
```
