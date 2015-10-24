package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChallenge9(t *testing.T) {
	a := []byte("YELLOW SUBMARINE")
	b := pks7Pad(a, 25)

	validatePks7Padded(b)
	assert.True(t, isPks7Padded(b))
	assert.Equal(t, 0, len(b)%25)
	assert.Equal(t, []byte{89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 9, 9, 9, 9, 9, 9, 9, 9, 9}, b)
}

func TestChallenge10(t *testing.T) {
	message := []byte("Some secret text that I want to keep secret.")
	key := []byte("My cOO1 Key. wow")
	blockSize := len(key)
	iv := make([]byte, blockSize)

	assert.Equal(t, message, pks7Unpad(decryptAESCBC(encryptAESCBC(message, iv, key), iv, key)))

	message = readBase64File("data/10.txt")
	key = []byte("YELLOW SUBMARINE")
	blockSize = len(key)
	iv = make([]byte, blockSize)

	assert.Equal(t, message, pks7Unpad(decryptAESCBC(encryptAESCBC(message, iv, key), iv, key)))

}

func TestChallenge11(t *testing.T) {
	message := []byte("YELLOW SUBMARINE")

	// Ensure message has some repeated blocks
	message = append(message, message...)
	message = append(message, message...)

	// Get counts of randomly cipher'd text
	isECBCount := map[bool]float64{true: 0.1, false: 0.1}
	for i := 0; i < 10000; i++ {
		cipher := randomAESCipher(message, 16)
		isECBCount[isAESECB(cipher, 16)]++
	}

	// Should be roughly 1:1
	assert.InEpsilon(t, 1, isECBCount[true]/isECBCount[false], 0.1)
}

// TODO: This takes way to long; speed it up
func TestChallenge12(t *testing.T) {
	// Verify it's ECB
	ciphertext := ecbCipherOracle([]byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE"))
	blockSize := detectECBBlockSize(ecbCipherOracle)
	assert.True(t, isAESECB(ciphertext, blockSize))

	// Crack it
	message := crackECB(ecbCipherOracle)
	assert.Equal(t, []byte("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"), message)
}

func TestChallenge13(t *testing.T) {
	// Create encrypted profile where the "role=" portion ends a block
	encryptedAttackerProfile := encryptedProfileFor("attackerXXXXXXXX@example.com")
	encryptedAdminProfile := encryptedProfileFor("XXXXXXXXXXadmin")

	// Create encrypted profile where "admin" is the beginning of a block
	attackerHalf := encryptedAttackerProfile[0:48]
	adminHalf := encryptedAdminProfile[16:32]

	// Stick the two together and decrypt for a poisoned profile
	newCipher := append(attackerHalf, adminHalf...)
	newProfile := decryptAESECB(newCipher, unknownOracleKey)
	assert.Equal(t, "email=attackerXXXXXXXX%40example.com&id=10&role=admin&id=10&role", string(newProfile))
}

// TODO: Doesn't really work yet, need to finish
func TestChallenge14(t *testing.T) {
	// oracle := ecbCipherWithPrependOrcale
	// fmt.Println(string(crackECB(oracle)))
}

func TestChallenge15(t *testing.T) {
	tests := map[string]bool{
		"ICE ICE BABY\x04\x04\x04\x04": true,
		"ICE ICE BABY\x05\x05\x05\x05": false,
		"ICE ICE BABY\x01\x02\x03\x04": false,
	}

	for str, shouldBeValid := range tests {
		assert.Equal(t, shouldBeValid, isPks7Padded([]byte(str)))
	}
}

func TestChallenge16(t *testing.T) {
	// Create a valid user profile and encrypt it
	message := []byte(prepareUserData("1234567890123456-admin-true"))
	iv := make([]byte, 16)
	key := []byte("YELLOW SUBMARINE")
	cipher := encryptAESCBC(message, iv, key)

	// Change hyphens to characters that are sanitized out of the prepareUserData input
	cipher[32] ^= '-' ^ ';'
	cipher[38] ^= '-' ^ '='

	// Decrypt it and we are now and admin
	poisonedProfile := decryptAESCBC(cipher, iv, key)
	assert.Contains(t, string(poisonedProfile), ";admin=true;")
}
