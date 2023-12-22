package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

var (
	timeFormat = "2006-01-02 15:04:05"
)

type JWT struct {
	header  map[string]string
	payload map[string]interface{}
	Alg     Algorithm
	secret  interface{}
	mu      sync.RWMutex
}

func New(alg Algorithm, secret interface{}, payload map[string]interface{}) *JWT {
	header := map[string]string{
		"typ": "JWT",
		"alg": alg.Name(),
	}
	p := map[string]interface{}{}
	if payload != nil {
		for k, v := range payload {
			p[k] = v
		}
	}
	return &JWT{
		header:  header,
		payload: p,
		Alg:     alg,
		secret:  secret,
	}
}

func Decode(token string, secret interface{}) (*JWT, error) {
	payload, header, err := decodeToken(token, secret)
	if err != nil {
		return nil, err
	}
	alg := header["alg"]
	algorithm, ok := GetAlgorithm(alg)
	if !ok {
		return nil, &DecodeError{msg: fmt.Sprintf("jwt decode: not support algorithm '%s'", alg)}
	}
	return &JWT{
		header:  header,
		payload: payload,
		Alg:     algorithm,
		secret:  secret,
	}, nil
}

func (jwt *JWT) SetClaim(name string, value interface{}) {
	jwt.mu.Lock()
	defer jwt.mu.Unlock()
	jwt.payload[name] = value
}

func (jwt *JWT) GetClaim(name string) interface{} {
	jwt.mu.RLock()
	defer jwt.mu.RUnlock()
	return jwt.payload[name]
}

func (jwt *JWT) Claims() map[string]interface{} {
	claims := make(map[string]interface{})
	jwt.mu.RLock()
	defer jwt.mu.RUnlock()
	for k, v := range jwt.payload {
		claims[k] = v
	}
	return claims
}

func (jwt *JWT) SetHeader(name string, value string) {
	jwt.mu.Lock()
	defer jwt.mu.Unlock()
	jwt.header[name] = value
}

func (jwt *JWT) GetHeader(name string) string {
	jwt.mu.RLock()
	defer jwt.mu.RUnlock()
	return jwt.header[name]
}

func (jwt *JWT) Headers() map[string]string {
	jwt.mu.RLock()
	defer jwt.mu.RUnlock()
	headers := make(map[string]string)
	for k, v := range jwt.header {
		headers[k] = v
	}
	return headers
}

func (jwt *JWT) Token() (string, error) {
	return encodeToken(jwt.payload, jwt.Alg, jwt.secret, jwt.header)
}

func (jwt *JWT) Parse(token string) error {
	payload, header, err := decodeToken(token, jwt.secret)
	if err != nil {
		return err
	} else {
		jwt.mu.Lock()
		defer jwt.mu.Unlock()
		jwt.Alg, _ = GetAlgorithm(header["alg"])
		jwt.header = header
		jwt.payload = payload
	}
	return nil
}

func encodeToken(payload map[string]interface{}, alg Algorithm, key interface{}, header map[string]string) (string, error) {
	jwtHeader := map[string]interface{}{
		"typ": "JWT",
	}
	if header != nil {
		for k, v := range header {
			jwtHeader[k] = v
		}
	}
	jwtHeader["alg"] = alg.Name()
	headerStr, err := encodeJson(jwtHeader)
	if err != nil {
		return "", &EncodeError{msg: fmt.Sprintf("jwt header encode:%s", err)}
	}
	payloadStr, err := encodeJson(payload)
	if err != nil {
		return "", &EncodeError{msg: fmt.Sprintf("jwt payload encode:%s", err)}
	}
	token := headerStr + "." + payloadStr
	signature, err := alg.Sign(token, key)
	if err != nil {
		return "", &EncodeError{msg: fmt.Sprintf("jwt sign error:%s", err)}
	}
	token = token + "." + signature
	return token, nil
}

func decodeToken(token string, key interface{}) (payload map[string]interface{}, header map[string]string, err error) {
	payload = map[string]interface{}{}
	header = map[string]string{}
	segments := strings.SplitN(token, ".", 3)
	if len(segments) != 3 {
		err = &DecodeError{msg: "wrong number of segments"}
		return
	}
	if err = decodeJson(segments[0], &header); err != nil {
		err = &DecodeError{msg: fmt.Sprintf("jwt header decode:%s", err)}
		return
	}
	if err = decodeJson(segments[1], &payload); err != nil {
		err = &DecodeError{msg: fmt.Sprintf("jwt payload decode:%s", err)}
		return
	}
	alg := header["alg"]
	algorithm, ok := GetAlgorithm(alg)
	if !ok {
		err = &DecodeError{msg: fmt.Sprintf("jwt decode: not support algorithm '%s'", alg)}
		return
	}
	ok, err = algorithm.Verify(segments[0]+"."+segments[1], segments[2], key)
	if err == nil && !ok {
		err = VerificationError
	}
	return
}

func encodeJson(value interface{}) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return encodeSegment(data), nil
}

func decodeJson(src string, dst interface{}) error {
	data, err := decodeSegment(src)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, dst)
	return err
}

func encodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}

func decodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}
