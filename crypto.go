package main

import (
	"crypto/aes"
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"math/rand"
	"sort"
)

//
// XOR
//

// calculateXor decrypts the secret with the given key using the repeating xor algorithm
func calculateXor(secret []byte, key []byte) []byte {
	message := make([]byte, len(secret))
	for i, b := range secret {
		message[i] = b ^ key[i%len(key)]
	}
	return message
}

// crackSingleByteXor finds the probably key/message for a secret encrypted with the single byte XOR scheme
func crackSingleByteXor(secret []byte) (byte, []byte) {
	key := byte(0)
	message := []byte{}
	maxScore := float64(0)

	for i := 0; i < 256; i++ {
		attempt := calculateXor(secret, []byte{byte(i)})
		score := englishScore(attempt)

		if score > maxScore {
			maxScore = score
			key = byte(i)
			message = attempt
		}
	}

	return key, message
}

// crackRepeatingKeyXor tries to unencrypt a secret encrypted with a repeating XOR scheme
func crackRepeatingKeyXor(secret []byte) ([]byte, []byte) {
	probableKeyLengths := findProbableKeyLengths(secret, 3)
	keys := map[int][]byte{}
	messages := map[int][]byte{}
	wordScores := tupleSortList{}

	for _, possibleKeyLength := range probableKeyLengths {
		blocks := transposeSecret(secret, possibleKeyLength)

		key := []byte{}
		for i := 0; i < len(blocks); i++ {
			keyFragment, _ := crackSingleByteXor(blocks[i])
			key = append(key, keyFragment)
		}

		keys[possibleKeyLength] = key
		messages[possibleKeyLength] = calculateXor(secret, key)

		wordScores = append(wordScores, tuple{possibleKeyLength, englishScore(messages[possibleKeyLength])})
	}

	sort.Sort(wordScores)
	bestLength := wordScores[len(wordScores)-1].val

	return keys[bestLength], messages[bestLength]
}

//
// AES
//

func encryptAESECB(message []byte, key []byte) []byte {
	blockSize := 16

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	cipher := make([]byte, 0, len(message))
	for i := 0; i < len(message); i += blockSize {
		cipherBlock := make([]byte, blockSize)
		block.Encrypt(cipherBlock, message[i:i+blockSize])
		cipher = append(cipher, cipherBlock...)
	}

	return cipher
}

func decryptAESECB(secret []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	plaintext := make([]byte, 0, len(secret))
	for i := 0; i < len(secret); i += 16 {
		decodedBlock := make([]byte, 16)
		block.Decrypt(decodedBlock, secret[i:i+16])
		plaintext = append(plaintext, decodedBlock...)
	}

	return plaintext
}

func encryptAESCBC(message []byte, iv []byte, key []byte) []byte {
	blockSize := len(key)
	cipher := []byte{}

	if (len(message) % blockSize) > 0 {
		message = pks7Pad(message, blockSize)
	}
	for i := 0; i < len(message); i += blockSize {
		plainBlock := message[i : i+blockSize]
		cipherBlock := encryptAESECB(calculateXor(plainBlock, iv), key)
		iv = cipherBlock

		cipher = append(cipher, cipherBlock...)
	}

	return pks7Unpad(cipher)
}

func decryptAESCBC(secret []byte, iv []byte, key []byte) []byte {
	blockSize := len(key)
	plaintext := []byte{}

	for i := 0; i < len(secret); i += blockSize {
		cipherBlock := secret[i : i+blockSize]
		plaintext = append(plaintext, calculateXor(decryptAESECB(cipherBlock, key), iv)...)
		iv = cipherBlock
	}

	return plaintext
	// return pks7Unpad(plaintext)
}

func isAESECB(bytes []byte, blockSize int) bool {
	seenBytes := map[string]int{}
	for i := 0; i < len(bytes); i += blockSize {
		seenBytes[string(bytes[i:i+blockSize])]++
	}

	isECB := false
	for _, count := range seenBytes {
		if count > 1 {
			isECB = true
		}
	}

	return isECB
}

func crackECB(oracle oracleFunc) []byte {
	// Determine the size of the oracle's blocks. We will want to create rainbow
	// lookup tables using prefixes of one less than the block size
	blockSize := detectECBBlockSize(oracle)
	rainbowTablePrefixLength := blockSize - 1

	// Determine an upper bound on our secret size by encrypted an empty message
	secretLength := len(oracle([]byte{}))

	// A slice to hold our leaked secret bytes
	known := make([]byte, 0, secretLength)

	// Iterate until we have a found a pks7padded string, but limit to 10k iterations
	for i := 0; i < 4000; i++ {
		knownLength := len(known)

		// Build a table of hashes with the given prefix and one unknown byte at the end
		// The prefix is the last `blockSize-1` byes of the known text, prepended with 0s
		// if necessary
		rainbowTablePrefix := make([]byte, rainbowTablePrefixLength)
		for j := 0; j < rainbowTablePrefixLength; j++ {
			if knownLength-j < 1 {
				break
			}
			rainbowTablePrefix[rainbowTablePrefixLength-1-j] = known[knownLength-1-j]
		}

		table := buildECBTable(oracle, rainbowTablePrefix)

		// Repeatedly call the oracle with random amounts of padding so that eventually
		// the prefix+nextByte should be aligned perfectly in a block. This allows us to
		// not be concerned with whether or not the oracle prepends an unknown number of
		// byte to input. Limit this loop to 10k iterations max.
		for j := 0; j < 1; j++ {
			var nextByte byte
			foundNextByte := false

			// Send a random about of padding to the oracle which will append the secret
			//text and encrypt it. Eventually our next secret byte should align with a block
			message := make([]byte, blockSize+rand.Intn(16))
			// fmt.Println(message)
			cipher := oracle(message)

			// Scan the cipher for blocks in our lookup table.
			for k := 0; k < len(cipher); k += blockSize {
				b, ok := table[string(cipher[k:k+blockSize])]
				if ok && b != byte(0) {
					nextByte = b
					foundNextByte = true
					break
				}
			}

			// We found the byte so append to it our known text and start looking for the next
			if foundNextByte {
				known = append(known, nextByte)
				break
			}
		}

		if isPks7Padded(known) {
			fmt.Println("Done.")
			return pks7Unpad(known)
		}
	}

	return known
}

func buildECBTable(oracle oracleFunc, prefix []byte) map[string]byte {
	blockSize := len(prefix) + 1
	table := map[string]byte{}

	for i := 0; i < 256; i++ {
		b := byte(i)
		message := append(prefix, b)

		block, _ := ecbEncryptedChunkFor(oracle, message, blockSize, 3)

		table[string(block)] = b
	}

	return table
}

func detectECBBlockSize(oracle oracleFunc) int {
	// Number of repeating chunks to look for
	repeatCount := 17

	for blockSizeAttempt := 1; blockSizeAttempt < 128; blockSizeAttempt++ {
		plaintext := make([]byte, blockSizeAttempt)
		for i := 0; i < blockSizeAttempt; i++ {
			plaintext[i] = 'A'
		}

		newPlaintext := make([]byte, 0, blockSizeAttempt*repeatCount)
		for i := 0; i < repeatCount; i++ {
			newPlaintext = append(newPlaintext, plaintext...)
		}

		cipher := oracle(newPlaintext)

		_, count := findMostCommonBlock(cipher, blockSizeAttempt)

		// We found the correct number (it may not be a perfect boundary so we'll only find repleatCount-1)
		if count == repeatCount || count == repeatCount-1 {
			return blockSizeAttempt
		}
	}

	return 0
}

func ecbEncryptedChunkFor(oracle oracleFunc, plaintext []byte, blockSize int, repeatCount int) ([]byte, int) {
	// newPlaintext := make([]byte, 0, repeatCount)
	for i := 0; i < repeatCount; i++ {
		plaintext = append(plaintext, plaintext...)
	}

	return findMostCommonBlock(oracle(plaintext), blockSize)
}

func findMostCommonBlock(bytes []byte, blockSize int) ([]byte, int) {
	// Find maximum number of repeating blocks in the cipertext
	count := 1
	maxCount := 1
	var maxChunk []byte
	var prev []byte
	for i := 0; i < len(bytes); i += blockSize {
		// Ciphertext should be an even multiple of the block size so if
		// this isn't we can just skip it
		if (len(bytes) % blockSize) > 0 {
			continue
		}

		chunk := bytes[i : i+blockSize]

		if string(chunk) == string(prev) {
			count++
		} else {
			count = 1
		}

		if count > maxCount {
			maxCount = count
			maxChunk = chunk
		}

		prev = chunk
	}

	return maxChunk, maxCount
}

// transposeSecret treats the secret as a keyLength X y matrix and transposes it
func transposeSecret(secret []byte, keyLength int) [][]byte {
	transposed := make([][]byte, keyLength)
	for i := 0; i < keyLength; i++ {
		transposed[i] = []byte{}
	}

	for i, b := range secret {
		idx := i % keyLength
		transposed[idx] = append(transposed[idx], b)
	}

	return transposed
}

// findProbableKeyLengths returns the `keyCount` most likely key lengths
// using very basic statistical analysis
func findProbableKeyLengths(data []byte, keyCount int) []int {
	distances := tupleSortList{}

	for keyLength := 1; keyLength < 50; keyLength++ {
		var dist float64
		for i := 0; i < 3; i++ {
			dist += float64(hammingDistance(data[0:keyLength], data[(i+1)*keyLength:(i+2)*keyLength])) / float64(keyLength) / 3.0
		}

		distances = append(distances, tuple{keyLength, dist})
	}

	sort.Sort(distances)

	lengths := make([]int, keyCount)
	for i := 0; i < keyCount; i++ {
		lengths[i] = distances[i].val
	}

	return lengths
}

//
// PKS7
//

func pks7Pad(data []byte, blockSize int) []byte {
	paddedData := data
	padSize := blockSize - (len(data) % blockSize)
	for i := padSize; i > 0; i-- {
		paddedData = append(paddedData, byte(padSize))
	}
	return paddedData
}

func pks7Unpad(data []byte) []byte {
	if !isPks7Padded(data) {
		return data
	}

	dataLength := len(data)
	padLength := int(data[dataLength-1])

	return data[0 : dataLength-padLength]
}

func isPks7Padded(data []byte) bool {
	dataLength := len(data)
	if dataLength == 0 {
		return false
	}

	padLength := int(data[dataLength-1])

	if padLength == 0 || dataLength < padLength {
		return false
	}

	for i := 0; i < padLength; i++ {
		if int(data[dataLength-i-1]) != padLength {
			return false
		}
	}

	return true
}

func validatePks7Padded(data []byte) {
	if !isPks7Padded(data) {
		panic("Data must be pks7 padded")
	}
}

//
// Oracles
//
var unknownOracleKey []byte
var unknownECBOracleSecret []byte

func prepareCipherOracles() {
	var err error

	if unknownOracleKey == nil {
		unknownOracleKey = make([]byte, 16)
		_, err := crand.Read(unknownOracleKey)
		if err != nil {
			panic(err)
		}
	}

	unknownECBOracleSecret, err = base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	if err != nil {
		panic(err)
	}
}

func ecbCipherOracle(message []byte) []byte {
	prepareCipherOracles()

	message = append(message, unknownECBOracleSecret...)
	message = pks7Pad(message, 16)

	return encryptAESECB(message, unknownOracleKey)
}

func ecbCipherWithPrependOrcale(message []byte) []byte {
	randomPrefix := make([]byte, rand.Intn(128))
	_, err := crand.Read(randomPrefix)
	if err != nil {
		panic(err)
	}

	message = append(randomPrefix, message...)

	return ecbCipherOracle(message)
}

func cbcPaddingOracle(iv []byte) []byte {
	prepareCipherOracles()

	possibleMessages := [][]byte{
		base64ToBytes("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="),
		base64ToBytes("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="),
		base64ToBytes("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="),
		base64ToBytes("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="),
		base64ToBytes("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"),
		base64ToBytes("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="),
		base64ToBytes("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="),
		base64ToBytes("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="),
		base64ToBytes("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="),
		base64ToBytes("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"),
	}

	message := possibleMessages[rand.Intn(len(possibleMessages))]

	return encryptAESCBC(message, iv, unknownOracleKey)
}

// TODO: this should use unknownOracleKey instead of accepting a key param
func checkEncryptedCNCPadding(cipher []byte, iv []byte, key []byte) bool {
	return isPks7Padded(decryptAESCBC(cipher, iv, key))
}
