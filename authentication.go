package main

// Pure Go sha1 implementation copied from crypto/sha1
import (
	"github.com/tyler-smith/matasano-cryptopals/sha1"
)

// Sha1KeyedMAC prepends a key to the message and returns the sha1 digest
func Sha1KeyedMAC(key []byte, message []byte) []byte {
	h := sha1.New()
	h.Write(append(key, message...))
	return h.Sum(nil)
}
