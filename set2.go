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
	secret := readBase64File("10.txt")

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
func Challenge13() {
}

// Challenge14 performs Matasano crypto challenge #14
func Challenge14() {
	oracle := ecbCipherWithPrependOrcale
	fmt.Println(string(crackECB(oracle)))

}

// Challenge15 performs Matasano crypto challenge #15
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
