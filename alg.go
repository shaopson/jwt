package jwt

import "sync"

var algorithms = map[string]Algorithm{}
var mutex sync.RWMutex

type Algorithm interface {
	Name() string
	Sign(src string, key interface{}) (string, error)
	Verify(s string, signature string, key interface{}) (bool, error)
}

func Register(name string, alg Algorithm) {
	mutex.Lock()
	defer mutex.Unlock()
	algorithms[name] = alg
}

func GetAlgorithm(name string) (Algorithm, bool) {
	mutex.RLock()
	defer mutex.RUnlock()
	alg, ok := algorithms[name]
	return alg, ok
}
