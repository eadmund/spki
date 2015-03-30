API design
==========

Generate a keypair:

    key, err := GeneratePrivateKey("(ecdsa (curve p256))")
    publicKey := key.PublicKey()
    // print either or both
    
Create a PublicKey by parsing an encoded public key:

    publicKey, err := EvalPublicKey(…)
    
Create a delegable certificate granting some authorisation to the PublicKey:

    tag, _, err := sexprs.Parse("(dns (* prefix com.example.))")
    if err != nil { … }
    validity := spki.Valid{NotBefore: date.Date(2014, date.January, 1, 0, 0, 0, 0, date.UTC),
                           NotAfter:  date.Date(2014, date.December, 31, 23, 59, 59, 0, 0, date.UTC)}
    cert := key.IssueAuthCert(publicKey, tag, validity)
    
Sign the certificate:

    sig := key.SignCert(cert)
    
Generate an SPKI sequence containing the cert and the signature:

    sequence := Sequence{cert, sig}
    
Return the canonical S-expression for sequence:

    sequence.Pack()
    
Create a certificate referring to a hash of the key:

    cert := key.IssueAuthCert(publicKey.Hashed(), tag, validity)
    
Create a more complex certificate:

    cert := spki.AuthCert{Issuer:   key,
                          Subject:  publicKey.Hashed(),
                          Validity: validity,
                          Delegate: false,
                          Tag:      tag}

Create a name certificate:

    nameCert := key.IssueNameCert(publicKey, []byte("Example, Inc."), validity)
    
N.b.: per RFC2683, 'Self' is a reserved issuer.
