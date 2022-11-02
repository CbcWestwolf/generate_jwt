package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	jwaRepo "github.com/lestrrat-go/jwx/v2/jwa"
	jwsRepo "github.com/lestrrat-go/jwx/v2/jws"
	jwtRepo "github.com/lestrrat-go/jwx/v2/jwt"
	"log"
	"time"

	jwkRepo "github.com/lestrrat-go/jwx/v2/jwk"
)

var (
	privateKeyString = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAq8G5n9XBidxmBMVJKLOBsmdOHrCqGf17y9+VUXingwDUZxRp
2XbuLZLbJtLgcln1lC0L9BsogrWf7+pDhAzWovO6Ai4Aybu00tJ2u0g4j1aLiDds
y0gyvSb5FBoL08jFIH7t/JzMt4JpF487AjzvITwZZcnsrB9a9sdn2E5B/aZmpDGi
2+Isf5osnlw0zvveTwiMo9ba416VIzjntAVEvqMFHK7vyHqXbfqUPAyhjLO+iee9
9Tg5AlGfjo1s6FjeML4xX7sAMGEy8FVBWNfpRU7ryTWoSn2adzyA/FVmtBvJNQBC
MrrAhXDTMJ5FNi8zHhvzyBKHU0kBTS1UNUbP9wIDAQABAoIBAFF0sbz82imwje2L
RvP3lfXvClyBulpTHigFJEKcLw1xEkrEoqKQxcp1UFvsPKfexBn+9yFQ0/iRfIWC
m3x/vjdP0ZKBELybudkWGVsemDxadhgm+QC7f9y3I/+FjsBlAiA0MlfQYUJSpdaX
hgu8rEgdwYnFpunGgRRyY2xxSNirEAzA6aTa1PkNU6W7nF5trOUOfdUSNZuPsS4y
rQjZJZDxB4SW+biuTqNAOKPPnnFY3PdntQx9uhcSm+qiDP2yQXoXuDK/TAN4euOK
vR5POnnDNKhFizGnR8xjW8GSmfg9ILxw/BpNFoIkvZo5xLtt7lNM2VPJaLzXEse2
axOpKckCgYEA2g8GWQOmqH8M4LaOxZcy+4dvoOou4vv+V5Bn4TDtmRaQd40BqfOZ
jyi9sci7iGYVsHdSpLlLFcXedx97QKstJZZ8RKQZv/wBZ7JH6Hn80ipGnJ3a7S9+
JY99iVDF6hOroR2fbnrqa/Dx8pPdMy9ZOXZvh3Q527j8u4m9zXUXfVUCgYEAyaRG
dSEt/AJxoecZqa450H8rlOQVDC0DcQcxGlEP7L2wQRinnJkfZ6+r7jhfu4SikOZO
MdXDF/ILGxSXw6+0xHwq9XfSlNhgTTcBNZOYfchMi6mvUxe/r4TsMXEcbRPSsuWo
EZJ1oZLHxdw9B96R9blnxk54VvILG60rrwbaOBsCgYEAz8EQ4y4/Urn5ov9L96We
xVa8XCvCkDBWm0bSMhNTzE9bRQvrUejtnR/L297MDaB1ebO14YtIpm3nDsfHvk1Y
rj86FovinK+VBx8ss6nF3ta4f+9F7kUZgt+7U2DJr8Md+lsm0zP4tO7TFbMbRPEP
qVfV2tA5b8ZHxMXvOBkfUCECgYAZbFvx0rAgkRJQrnme2jex4QbWq/c3ZMmFS7nW
LphKahQ58OjZJrk98nlD/NmdI/j3OgJr6B7D+yGJVYxZAONSzrD/6A6l864YrjG5
1pUobsOv7EINwPXLJIA/L5q86f3rzmblaEjqiT4k5ULQpjBTAgBikWw80iGyaKAU
XlHPNwKBgQDC45gv8aRxJXwSjpCXHnnzoWAJHBOXIpTbQOVdGbuMRr5RAh4CVFsp
6rnNlannpnE8EMkLtAmPLNqmsP0XCRo2TpHU86PRO3OGH/3KEtU/X3ij9sts2OlM
03m9HNt6/h9glwk7NYwbGgOlKhRxr/DUTkumu0tdfYN+tLU83mBeNw==
-----END RSA PRIVATE KEY-----`

	sub    = flag.String("sub", "user", "The 'sub' of the JWT")
	email  = flag.String("email", "email", "The 'email' of the JWT")
	iat    = flag.Int64("iat", time.Now().Unix(), "The 'iat' of the JWT")
	exp    = flag.Int64("exp", time.Now().Add(15*time.Minute).Unix(), "The 'exp' of the JWT")
	iss    = flag.String("iss", "issuer", "The 'iss' of the JWT")
	kid    = flag.String("kid", "kid-abc", "The 'kid' of the header")
	priKey *rsa.PrivateKey
	pubKey *rsa.PublicKey
)

type pair struct {
	name  string
	value interface{}
}

func init() {
	var ok bool
	if v, rest, err := jwkRepo.DecodePEM(([]byte)(privateKeyString)); err != nil {
		log.Println(err.Error())
		log.Fatal("Error in decode private key")
	} else if len(rest) > 0 {
		log.Fatal("Rest in decode private key")
	} else if priKey, ok = v.(*rsa.PrivateKey); !ok {
		log.Fatal("Wrong type of private key")
	}
}

func main() {
	jwt := jwtRepo.New()
	var signedTokenString []byte
	var err error

	claims := []pair{
		{jwtRepo.SubjectKey, *sub},
		{"email", *email},
		{jwtRepo.IssuedAtKey, *iat},
		{jwtRepo.ExpirationKey, *exp},
		{jwtRepo.IssuerKey, *iss},
	}
	for _, claim := range claims {
		if err = jwt.Set(claim.name, claim.value); err != nil {
			log.Println(claim.name, claim.value)
			log.Fatal("Error when set claim")
		}
	}
	header := jwsRepo.NewHeaders()
	headers := []pair{
		{jwsRepo.AlgorithmKey, jwaRepo.RS256},
		{jwsRepo.KeyIDKey, *kid},
		{jwsRepo.TypeKey, "JWT"},
	}
	for _, h := range headers {
		if err = header.Set(h.name, h.value); err != nil {
			log.Println(h.name, h.value)
			log.Fatal("Error when set header")
		}
	}
	if signedTokenString, err = jwtRepo.Sign(jwt, jwtRepo.WithKey(jwaRepo.RS256, priKey, jwsRepo.WithProtectedHeaders(header))); err != nil {
		log.Println(err)
		log.Fatal("Error when sign")
	} else {
		fmt.Println(string(signedTokenString))
	}
}
