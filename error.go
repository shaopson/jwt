package jwt

import "errors"

var (
	VerificationError = errors.New("Algorithm verification error")
)

type EncodeError struct {
	msg string
}

func (e *EncodeError) Error() string {
	return e.msg
}

type DecodeError struct {
	msg string
}

func (e *DecodeError) Error() string {
	return e.msg
}
