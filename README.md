# jwt
A golang implementation of JWT, support hs256, hs384, hs512, rs256, rs384, rs512 sign algorithms

## install
```shell
go get -u github.com/shaopson/jwt
```

## Quick start

```go
package main

import (
	"fmt"
	"github.com/shaopson/jwt"
)

func main() {
	secret := "test-key"
	t := jwt.New(jwt.HS256, secret, nil)
	t.SetClaim("uid", 1234)
	t.SetClaim("username", "user1234")
	token, err := t.Token()
	if err != nil {
		panic(err)
	}
	fmt.Println("jwt:",token)
	
	//
	t, err = jwt.Decode(token, secret)
	if err != nil {
		panic(err)
	}
	v := t.GetClaim("uid")
	uid := v.(int)
	fmt.Println("uid", uid)
}

```

## Algorithms
support: hmac(hs256,hs384,hs512), rsa(rs256,rs384,rs512)


### HMAC
```go
secret := "test-key"
// HS256
t := jwt.New(jwt.HS256, secret, nil)
// HS384
t := jwt.New(jwt.HS384, secret, nil)
// HS512
t := jwt.New(jwt.HS512, secret, nil)

```

### RSA

```go
// generates an RSA keypair
privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
// rs256
t := jwt.New(jwt.RS256, privateKey, nil)
// encode
token, err := t.Tokan()
// decode
t, err = jwt.Decode(token, &privateKey.PublicKey)

```
#### Pem encoding RSA key
```go
private, public, err := GenRSAKey(1024)

t := jwt.New(jwt.RS384, private)

t, err = jwt.Decode(token, public)
```