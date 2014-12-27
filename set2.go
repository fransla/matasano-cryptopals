package main

import "fmt"

// Challenge9 performs Matasano crypto challenge #9
func Challenge9() {
	a := []byte("YELLOW SUBMARINE")
	b := pks7Pad(a, 20)
	fmt.Println("Before:      ", a)
	fmt.Println("Padded to 20:", b)
}

// Challenge10 performs Matasano crypto challenge #10
func Challenge10() {
	// My test
	message := []byte("Some secret text that I want to keep secret.")
	key := []byte("My cOO1 Key. wow")
	blockSize := len(key)
	iv := make([]byte, blockSize)

	cipher := encryptAESCBC(message, iv, key)

	newMessage := decryptAESCBC(cipher, iv, key)
	fmt.Println("Encrypted/Decrypted message:")
	fmt.Println(string(newMessage))

	// Matasano test
	secret := readBase64File("data/10.txt")

	key = []byte("YELLOW SUBMARINE")
	blockSize = len(key)
	iv = make([]byte, blockSize)

	message = decryptAESCBC(secret, iv, key)
	fmt.Println(string(message))
}

// Challenge11 performs Matasano crypto challenge #11
func Challenge11() {
	message := []byte("YELLOW SUBMARINE")

	// Ensure message has some repeated blocks
	message = append(message, message...)
	message = append(message, message...)

	ecbCount := 0.1
	cbcCount := 0.1

	for i := 0; i < 10000; i++ {
		cipher := randomAESCipher(message, 16)
		if isAESECB(cipher, 16) {
			ecbCount++
		} else {
			cbcCount++
		}
	}

	ratio := ecbCount / cbcCount
	if (1 - ratio) < 0.1 {
		fmt.Println("Detected about 1:1 ECB:CBC which is good")
	} else {
		fmt.Println("Ratio should be about 1:1 but it is", ratio)
	}
}

// Challenge12 performs Matasano crypto challenge #12
// Crack a secret string appened by an encryption oracle using ECB byte-by-byte
func Challenge12() {
	// Verify it's ECB
	ciphertext := ecbCipherOracle([]byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE"))
	blockSize := detectECBBlockSize(ecbCipherOracle)
	if isAESECB(ciphertext, blockSize) {
		fmt.Println("Oracle function is ECB")
	} else {
		fmt.Println("Oracle function is not ECB")
		return
	}

	// Crack it
	fmt.Println(string(crackECB(ecbCipherOracle)))
}

// Challenge13 performs Matasano crypto challenge #13
// Mangle encrypted profiles to build an admin profile
// TODO: This leaves a trailing "&role=user" which should be fixed
func Challenge13() {
	encryptedAttackerProfile := encryptedProfileFor("attackerXXXXXX@example.com")
	encryptedAdminProfile := encryptedProfileFor("XXadmin")

	attackerHalf := encryptedAttackerProfile[0:48]
	adminHalf := encryptedAdminProfile[16:32]

	newCipher := append(attackerHalf, adminHalf...)
	fmt.Println(newCipher)

	newProfile := decryptAESECB(newCipher, unknownECBOracleKey)
	fmt.Println(string(newProfile))
}

// Challenge14 performs Matasano crypto challenge #14
// TODO: Doesn't really work yet, need to finish
func Challenge14() {
	oracle := ecbCipherWithPrependOrcale
	fmt.Println(string(crackECB(oracle)))

}

// Challenge15 performs Matasano crypto challenge #15
// Validte pks7 padding
func Challenge15() {
	tests := map[string]bool{
		"ICE ICE BABY\x04\x04\x04\x04": true,
		"ICE ICE BABY\x05\x05\x05\x05": false,
		"ICE ICE BABY\x01\x02\x03\x04": false,
	}

	for str, shouldBeValid := range tests {
		isValid := isPks7Padded([]byte(str))
		fmt.Println("Should be", shouldBeValid, ":", isValid)
	}
}

// Challenge16 performs Matasano crypto challenge #16
func Challenge16() {
	// Create a valid user profile and encrypt it
	message := []byte(prepareUserData("1234567890123456-admin-true"))
	iv := []byte("AAAAAAAAAAAAAAAA")
	key := []byte("YELLOW SUBMARINE")
	cipher := encryptAESCBC(message, iv, key)

	// Change hyphens to characters that are sanitized out of the prepareUserData input
	cipher[32] ^= '-' ^ ';'
	cipher[38] ^= '-' ^ '='

	// Decrypt it and we are now and admin
	fmt.Println(string(decryptAESCBC(cipher, iv, key)))
}
