package jwt

import (
	"crypto"
	"crypto/hmac"
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
	var salt []byte
	switch key.(type) {
	case []byte:
		salt = key.([]byte)
	case string:
		salt = []byte(key.(string))
	default:
		return "", fmt.Errorf("%s sign fail, invalid key:'%s'", alg.name, key)
	}
	if !alg.hash.Available() {
		return "", fmt.Errorf("Hash '%s' is not availd", alg.hash)
	}
	hash := hmac.New(alg.hash.New, salt)
	hash.Write([]byte(src))
	return EncodeSegment(hash.Sum(nil)), nil
}

func (alg *HmacAlg) Verify(s, signature string, key interface{}) error {
	if ss, err := alg.Sign(s, key); err != nil {
		return err
	} else if ss != signature {
		return ErrVerifyFail
	}
	return nil
}
