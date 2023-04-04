package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

var (
	RS256 Algorithm = &RsaAlg{name: "RS256", hash: crypto.SHA256}
	RS384 Algorithm = &RsaAlg{name: "RS384", hash: crypto.SHA384}
	RS512 Algorithm = &RsaAlg{name: "RS512", hash: crypto.SHA512}
)

func init() {
	Register(RS256.Name(), RS256)
	Register(RS384.Name(), RS384)
	Register(RS512.Name(), RS512)
}

// genarate pem encoding string private key and public key
func GenRSAKey(length int) (private string, public string, err error) {
	// 生成RSA密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, length)
	if err != nil {
		return "", "", err
	}
	// 将私钥序列化为ASN.1 DER编码
	dePri := x509.MarshalPKCS1PrivateKey(privateKey)
	dePub := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)

	// 将DER编码的私钥放入PEM块中
	pemPriBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: dePri,
	}
	pemPubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: dePub,
	}
	// 将PEM块编码为字符串
	private = string(pem.EncodeToMemory(pemPriBlock))
	public = string(pem.EncodeToMemory(pemPubBlock))
	return
}

func ParseRSAPrivateKey(pemString string) (*rsa.PrivateKey, error) {
	// 解码PEM块
	pemBlock, _ := pem.Decode([]byte(pemString))
	// 解析DER编码的私钥
	return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
}

func ParseRSAPublicKey(pemString string) (*rsa.PublicKey, error) {
	// 解码PEM块
	pemBlock, _ := pem.Decode([]byte(pemString))
	// 解析DER编码的公钥
	return x509.ParsePKCS1PublicKey(pemBlock.Bytes)
}

type RsaAlg struct {
	name string
	hash crypto.Hash
}

func (alg *RsaAlg) Name() string {
	return alg.name
}

func (alg *RsaAlg) Sign(src string, key interface{}) (string, error) {
	var privateKey *rsa.PrivateKey
	var err error
	if !alg.hash.Available() {
		return "", fmt.Errorf("Hash '%s' is not availd", alg.hash)
	}
	switch key.(type) {
	case *rsa.PrivateKey:
		privateKey = key.(*rsa.PrivateKey)
	case string:
		keyString := key.(string)
		if strings.Index(keyString, "-BEGIN RSA PRIVATE KEY-") > 0 {
			privateKey, err = ParseRSAPrivateKey(keyString)
		}
	case []byte:
		keyString := string(key.([]byte))
		if strings.Index(keyString, "-BEGIN RSA PRIVATE KEY-") > 0 {
			privateKey, err = ParseRSAPrivateKey(keyString)
		}
	default:
		return "", fmt.Errorf("%s sign fail, invalid private key:'%s'", alg.name, key)
	}
	if privateKey == nil {
		return "", fmt.Errorf("%s sign fail, invalid private key:'%s'", alg.name, key)
	}
	hash := alg.hash.New()
	hash.Write([]byte(src))
	hashedData := hash.Sum(nil)
	data, err := rsa.SignPKCS1v15(rand.Reader, privateKey, alg.hash, hashedData)
	if err != nil {
		return "", err
	}
	return EncodeSegment(data), nil
}

func (alg *RsaAlg) Verify(s, signature string, key interface{}) error {
	var publicKey *rsa.PublicKey
	var err error
	if !alg.hash.Available() {
		return fmt.Errorf("Hash '%s' is not availd", alg.hash)
	}
	switch key.(type) {
	case *rsa.PublicKey:
		publicKey = key.(*rsa.PublicKey)
	case *rsa.PrivateKey:
		if ss, err := alg.Sign(s, key.(*rsa.PrivateKey)); err != nil {
			return err
		} else if ss != signature {
			return ErrVerifyFail
		}
		return nil
	case string:
		keyString := key.(string)
		if strings.Index(keyString, "-BEGIN PUBLIC KEY-") > 0 {
			publicKey, err = ParseRSAPublicKey(keyString)
		}
	case []byte:
		keyString := string(key.([]byte))
		if strings.Index(keyString, "-BEGIN PUBLIC KEY-") > 0 {
			publicKey, err = ParseRSAPublicKey(keyString)
		}
	default:
		return fmt.Errorf("%s verify fail, invalid public key:'%s'", alg.name, key)
	}
	if publicKey == nil {
		return fmt.Errorf("%s verify fail, invalid public key:'%s'", alg.name, key)
	}
	sig, err := DecodeSegment(signature)
	if err != nil {
		return err
	}
	hash := alg.hash.New()
	hash.Write([]byte(s))
	data := hash.Sum(nil)
	return rsa.VerifyPKCS1v15(publicKey, alg.hash, data, sig)
}
