package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChallenge25(t *testing.T) {
	key := randomBytes(16)

	// First test edit function
	p1 := "YELLOW SUBMARINEYELLOW SUBMARINE"
	p2 := "JELLOW SUBMARINEJELLOW SUBMARINE"

	cipher1 := encryptAESCTR([]byte(p1), key)
	cipher2 := editAESCTR(cipher1, key, 0, []byte{'J'})
	cipher2 = editAESCTR(cipher2, key, 16, []byte{'J'})

	assert.Equal(t, []byte(p2), decryptAESCTR(cipher2, key))
}
