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
	oracle := unknownECBCipher

	blockSize := detectECBBlockSize(oracle)

	ciphertext := oracle([]byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE"))

	if isAESECB(ciphertext, blockSize) {
		fmt.Println("Oracle function is ECB")
	} else {
		fmt.Println("Oracle function is not ECB")
		return
	}

	// Determine the length of the secret we want to find, and for each byte construct
	// a table with each possible byte value right aligned in a padded block. Compare
	// it with a cipher of 1 less than blockSize to determine leaked byte
	// Repeat with prefix equal to padding + known text so far until we are done
	secretLength := len(oracle([]byte{}))
	known := make([]byte, 0, secretLength)
	targetBlockIdx := (secretLength / blockSize) - 1
	for i := secretLength - 1; i > 0; i-- {
		buffer := make([]byte, i)
		prefix := append(buffer, known...)

		table := buildECBTable(oracle, prefix, blockSize)

		cipher := oracle(buffer)
		block := cipher[targetBlockIdx*blockSize : (targetBlockIdx+1)*blockSize]

		b, ok := table[string(block)]
		if !ok {
			panic("Unknown cipher in table")
		}

		known = append(known, b)
	}

	fmt.Println(string(known))
}

// Challenge13 performs Matasano crypto challenge #13
func Challenge13() {
	// oracle := unknownECBCipherWithPrepend
	// message := []byte("YELLOW SUBMARINE")
	//
	// fmt.Println(oracle(message))
	// fmt.Println(oracle(message))
	// fmt.Println(oracle(message))
}
