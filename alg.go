package jwt

import "sync"

var algorithms = map[string]Algorithm{}
var mutex sync.RWMutex

type Algorithm interface {
	Name() string
	Sign(src string, key interface{}) (string, error)
	//verify signature value, if pass that will be return nil
	Verify(s string, signature string, key interface{}) error
}

func Register(name string, alg Algorithm) {
	mutex.Lock()
	defer mutex.Unlock()
	algorithms[name] = alg
}

func GetAlgorithm(name string) Algorithm {
	mutex.RLock()
	defer mutex.RUnlock()
	return algorithms[name]
}
