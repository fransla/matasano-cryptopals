package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChallenge25(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")

	nonce := make([]byte, 16)
	cipher := append(nonce, readBase64File("data/25.txt")...)
	message := decryptAESECB(cipher, key)

	cipher = ctrEditOracleEncrypter(message)

	// Editing the message to all 0s will yield the keystream
	keystream := ctrEditOracleEditor(cipher, 0, make([]byte, len(cipher[8:])))
	nonce = cipher[:8]
	cipher = cipher[8:]

	assert.Equal(t, message, calculateXor(cipher, keystream))
}

func TestChallenge26(t *testing.T) {
	// Create a valid user profile and encrypt it
	message := []byte(prepareUserData("1234567890123456-admin-true"))
	key := []byte("YELLOW SUBMARINE")
	cipher := encryptAESCTR(message, key)

	// Change hyphens to characters that are sanitized out of the prepareUserData input
	cipher[56] ^= '-' ^ ';'
	cipher[62] ^= '-' ^ '='

	// Decrypt it and we are now and admin
	poisonedProfile := decryptAESCTR(cipher, key)

	assert.Contains(t, string(poisonedProfile), ";admin=true;")
}
