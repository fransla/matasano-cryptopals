package main

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tyler-smith/matasano-cryptopals/sha1"
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

func TestChallenge27(t *testing.T) {
}

func TestChallenge28(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	message := []byte("This is a secret message")

	// Create SHA1(key || message) digest
	digest := hex.EncodeToString(Sha1KeyedMAC(key, message))

	// Test value calculated from Ruby for comparison
	assert.Equal(t, "2681227a67676278dff5c3b5ddc3851fc565ec41", digest)
}

func TestChallenge29(t *testing.T) {
	keyLength := 8
	randomKey := randomBytes(keyLength)

	createMAC := func(message []byte) []byte {
		return Sha1KeyedMAC(randomKey, message)
	}

	verifyMAC := func(message []byte, mac []byte) bool {
		if string(Sha1KeyedMAC(randomKey, message)) == string(mac) {
			return true
		}
		return false
	}

	// Create a hash for a chosen plaintext
	chosenPlaintext := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	chosenPlaintextMAC := createMAC(chosenPlaintext)
	assert.True(t, verifyMAC(chosenPlaintext, chosenPlaintextMAC))

	// Create poison message which sets admin=true
	// We create a message padded for message+keyLength bytes, but remove the first
	// keyLength bytes since they're junk. The victim will prepend their key and
	// then it will all line up
	poisonText := make([]byte, keyLength)
	poisonText = sha1Pad(append(poisonText, chosenPlaintext...))
	poisonText = poisonText[keyLength:]

	// Add the admin=true bit
	payload := []byte(";admin=true")
	poisonText = append(poisonText, payload...)

	// Create a Sha1 calculate pre-set to use regsiters and desired length
	sha1Forger := sha1.NewWithGivenRegisters(sha1HashToRegisters(chosenPlaintextMAC), uint64(len(poisonText)+keyLength))
	sha1Forger.Write(payload)
	forgedMAC := sha1Forger.Sum(nil)

	assert.True(t, verifyMAC(poisonText, forgedMAC))
}
