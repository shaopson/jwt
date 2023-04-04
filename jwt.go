package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrVerifyFail   = errors.New("Signature verify fail")
	ErrInvalidToken = errors.New("Invalid token")
)

type JWT struct {
	Header  map[string]interface{}
	Payload map[string]interface{}
	Alg     Algorithm
	secret  interface{}
}

func New(alg Algorithm, secret interface{}) *JWT {
	header := map[string]interface{}{
		"typ": "JWT",
		"alg": alg.Name(),
	}
	return &JWT{
		Header:  header,
		Payload: map[string]interface{}{},
		Alg:     alg,
		secret:  secret,
	}
}

func NewWithToken(token string, secret interface{}) (*JWT, error) {
	payload, header, err := Decode(token, secret)
	if err != nil {
		return nil, err
	}
	alg := header["alg"].(string)
	algorithm := GetAlgorithm(alg)
	return &JWT{
		Header:  header,
		Payload: payload,
		Alg:     algorithm,
		secret:  secret,
	}, nil
}

func (jwt *JWT) SetClaim(name string, value interface{}) {
	jwt.Payload[name] = value
}

func (jwt *JWT) GetClaim(name string) interface{} {
	return jwt.Payload[name]
}

func (jwt *JWT) SetHeader(name string, value interface{}) {
	jwt.Header[name] = value
}

func (jwt *JWT) GetHeader(name string) interface{} {
	return jwt.Header[name]
}

func (jwt *JWT) Token() (string, error) {
	return Encode(jwt.Payload, jwt.Alg, jwt.secret, jwt.Header)
}

func (jwt *JWT) Parse(token string) error {
	payload, header, err := Decode(token, jwt.secret)
	if err != nil {
		return err
	} else {
		jwt.Header = header
		jwt.Payload = payload
	}
	return nil
}

func Encode(payload map[string]interface{}, alg Algorithm, key interface{}, headers map[string]interface{}) (string, error) {
	jwtHeader := map[string]interface{}{
		"typ": "JWT",
	}
	for k, v := range headers {
		jwtHeader[k] = v
	}
	jwtHeader["alg"] = alg.Name()
	headerStr, err := JsonEncode(jwtHeader)
	if err != nil {
		return "", fmt.Errorf("Encode header error:%s", err)
	}
	payloadStr, err := JsonEncode(payload)
	if err != nil {
		return "", fmt.Errorf("Encode payload error:%s", err)
	}
	token := headerStr + "." + payloadStr
	signature, err := alg.Sign(token, key)
	if err != nil {
		return "", err
	}
	token += ("." + signature)
	return token, nil
}

func Decode(token string, key interface{}) (payload, header map[string]interface{}, err error) {
	payload = map[string]interface{}{}
	header = map[string]interface{}{}
	segments := strings.SplitN(token, ".", 3)
	if len(segments) != 3 {
		err = ErrInvalidToken
		return
	}
	if err = JsonDecode(segments[0], &header); err != nil {
		err = fmt.Errorf("Invalid token, header decode fail:%s", err)
		return
	}
	if err = JsonDecode(segments[1], &payload); err != nil {
		err = fmt.Errorf("Invalid token, payload decode fail:%s", err)
		return
	}
	alg := header["alg"].(string)
	if alg == "" {
		err = fmt.Errorf("Does not algorithm, header is missing the 'alg' parameter")
		return
	}
	algorithm := GetAlgorithm(alg)
	if algorithm == nil {
		err = fmt.Errorf("Not support algorithm:'%s'", alg)
		return
	}
	err = algorithm.Verify(segments[0]+"."+segments[1], segments[2], key)
	return
}

func JsonEncode(value interface{}) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return EncodeSegment(data), nil
}

func JsonDecode(src string, dst interface{}) error {
	data, err := DecodeSegment(src)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, dst)
	return err
}

func EncodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}

func DecodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}
