package jwt

import (
	"crypto"
	"crypto/hmac"
	"errors"
	"fmt"
)

var (
	HS256 Algorithm = &HmacAlg{name: "HS256", hash: crypto.SHA256}
	HS384 Algorithm = &HmacAlg{name: "HS384", hash: crypto.SHA384}
	HS512 Algorithm = &HmacAlg{name: "HS512", hash: crypto.SHA512}
)

func init() {
	Register(HS256.Name(), HS256)
	Register(HS384.Name(), HS384)
	Register(HS512.Name(), HS512)
}

type HmacAlg struct {
	name string
	hash crypto.Hash
}

func (alg *HmacAlg) Name() string {
	return alg.name
}

func (alg *HmacAlg) Sign(src string, key interface{}) (string, error) {
	if !alg.hash.Available() {
		return "", fmt.Errorf("hash function '%s' is unavailable", alg.hash)
	}
	var k []byte
	switch v := key.(type) {
	case []byte:
		k = v
	case string:
		k = []byte(v)
	default:
		return "", errors.New("hmac algorithm: key must be '[]byte', 'string' type.")
	}
	hash := hmac.New(alg.hash.New, k)
	hash.Write([]byte(src))
	return encodeSegment(hash.Sum(nil)), nil
}

func (alg *HmacAlg) Verify(s, signature string, key interface{}) (bool, error) {
	if ss, err := alg.Sign(s, key); err != nil {
		return false, err
	} else if ss != signature {
		return false, nil
	}
	return true, nil
}
