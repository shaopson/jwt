package jwt

import (
	"testing"
)

func TestJWT(t *testing.T) {
	key := "test-key"
	j := New(HS256, key, nil)
	j.SetClaim("uid", 1234)
	j.SetClaim("username", "shao")
	token, err := j.Token()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(token)

}
