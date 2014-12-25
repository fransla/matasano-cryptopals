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
