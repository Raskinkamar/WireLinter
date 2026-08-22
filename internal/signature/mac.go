package signature

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
)

func newMAC(algorithm string, secret []byte) (hash.Hash, error) {
	var hashFunc func() hash.Hash
	switch algorithm {
	case "hmac-sha1":
		hashFunc = sha1.New
	case "hmac-sha256":
		hashFunc = sha256.New
	default:
		return nil, fmt.Errorf("unsupported MAC algorithm %q", algorithm)
	}
	return hmac.New(hashFunc, secret), nil
}
