package main

import (
	"fmt"
	"testing"
)

func TestChallenge17(t *testing.T) {
	iv := []byte("YELLOW SUBMARINE")

	cipher := cbcPaddingOracle(iv)
	// fmt.Println(cipher)
	// fmt.Println(checkEncryptedCNCPadding(cipher, iv))

	message := []byte("TEST OH YEAHYEAHTEST OH YEAHYEA!")
	key := []byte("AAAAAAAAAAAAAAAA")
	cipher = encryptAESCBC(message, iv, key)
	blockSize := 16
	plaintext := make([]byte, len(cipher))
	// plaintext := make([]byte, 0, len(cipher))
	plaintextLength := len(cipher)

	cipherBlock1 := cipher[0:blockSize]
	cipherBlock2 := cipher[blockSize : 2*blockSize]

	fmt.Println(cipherBlock1)
	fmt.Println(cipherBlock2)
	// To decrypt we want the last byte of the real previous cipher block
	// The poision byte which decrypts to correct padding
	// And the padding byte itself which we will assume is 1 (the most likely)

	// poisonCipher := cipher

	var c byte
	var cPrime byte
	// var lastKnownByte byte
	for i := 1; i <= plaintextLength; i++ {
		poisonCipher := append(make([]byte, 0, plaintextLength), cipher...)
		c = poisonCipher[plaintextLength-blockSize-i]

		if i > 1 {
			// NOTES for resuming works: for some reason we are setting poisonCipher[j] to 34, not 2 (i)

			// Set all bytes after the one we want to leak to the padsize

			// fmt.Println("p1:", poisonCipher)
			for j := plaintextLength - blockSize - 1; j > plaintextLength-blockSize-i; j-- {
				// fmt.Println("lkb", lastKnownByte)
				// fmt.Println("cp:", cPrime)
				// fmt.Println("c:", c)
				// fmt.Println("i:", i)
				// fmt.Println("j:", j)
				// fmt.Println('!' ^ byte(208) ^ byte(2))
				// fmt.Println(poisonCipher)
				// fmt.Println(plaintext)

				poisonCipher[j] ^= plaintext[j+blockSize] ^ byte(i)

				// if i == 2 {
				// 	poisonCipher[j] = '!' ^ byte(208) ^ byte(2)
				// } else if i == 3 {
				// 	poisonCipher[j] = '!' ^ byte(208) ^ byte(3)
				// } else {
				//
				// 	// poisonCipher[j] = '!' ^ byte(208) ^ byte(3)
				// 	for a := 0; a < 256; a++ {
				// 		poisonCipher[j] = '!' ^ byte(a) ^ byte(i)
				// 		d := decryptAESCBC(poisonCipher, iv, key)
				// 		if d[len(d)-1] == byte(i) {
				// 			fmt.Println("FOUND!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!:", a)
				// 			return
				// 		}
				// 	}
				// }
				// fmt.Println(poisonCipher[j])
			}
			// fmt.Println("p2:", poisonCipher)
			// fmt.Println("p3:", string(poisonCipher) == string(a))
		}

		// fmt.Println("posion:", poisonCipher)
		foundCPrime := false
		for cPrimeAttempt := 0; cPrimeAttempt < 256; cPrimeAttempt++ {
			poisonCipher[plaintextLength-blockSize-i] = byte(cPrimeAttempt)
			// fmt.Println(decryptAESCBC(poisonCipher, iv, key))
			// if i > 3 {
			// 	break
			// }

			if checkEncryptedCNCPadding(poisonCipher, iv, key) {
				cPrime = byte(cPrimeAttempt)
				fmt.Println("FOUND:", cPrime)
				foundCPrime = true
				break
			}
		}
		if !foundCPrime {
			panic("No cprime found")
		}

		fmt.Println(i, cPrime, c)
		// lastKnownByte = c ^ cPrime ^ byte(i)
		// plaintext = append([]byte{lastKnownByte}, plaintext...)
		plaintext[plaintextLength-i] = c ^ cPrime ^ byte(i)
		// if i > 4 {
		//
		// 	break
		// }
		fmt.Println(string(plaintext))
	}

	fmt.Println(string(plaintext))
}
