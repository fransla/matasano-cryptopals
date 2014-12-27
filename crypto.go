package main

import (
	"crypto/aes"
	"fmt"
	"math/rand"
	"sort"
)

// crackSingleByteXor finds the probably key/message for a secret encrypted with the single byte XOR scheme
func crackSingleByteXor(secret []byte) (byte, []byte) {
	key := byte(0)
	message := []byte{}
	maxScore := float64(0)

	for i := byte(0); i < byte(255); i++ {
		attempt := calculateSingleByteXor(secret, byte(i))
		score := englishScore(attempt)

		if score > maxScore {
			maxScore = score
			key = i
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
		messages[possibleKeyLength] = calculateReapeatingXor(secret, key)

		wordScores = append(wordScores, tuple{possibleKeyLength, englishScore(messages[possibleKeyLength])})
	}

	sort.Sort(wordScores)
	bestLength := wordScores[len(wordScores)-1].val

	return keys[bestLength], messages[bestLength]
}

func crackECB(oracle cipherFunc) []byte {
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

func buildECBTable(oracle cipherFunc, prefix []byte) map[string]byte {
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

func detectECBBlockSize(oracle cipherFunc) int {
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

func ecbEncryptedChunkFor(oracle cipherFunc, plaintext []byte, blockSize int, repeatCount int) ([]byte, int) {
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

		if slicesAreEqual(chunk, prev) {
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

// calculateReapeatingXor decrypts the secret with the given key using the repeating xor algorithm
func calculateReapeatingXor(secret []byte, key []byte) []byte {
	message := make([]byte, len(secret))
	for i, b := range secret {
		message[i] = b ^ key[i%len(key)]
	}
	return message
}

func calculateSingleByteXor(secret []byte, other byte) []byte {
	newBytes := make([]byte, len(secret))
	copy(newBytes, secret)

	for i, b := range newBytes {
		newBytes[i] = b ^ other
	}

	return newBytes
}

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

	for i := 0; i < len(message); i += blockSize {
		plainBlock := message[i : i+blockSize]
		if len(plainBlock) < blockSize {
			plainBlock = pks7Pad(plainBlock, blockSize)
		}

		cipherBlock := encryptAESECB(calculateReapeatingXor(plainBlock, iv), key)
		cipher = append(cipher, cipherBlock...)
		iv = cipherBlock
	}

	return cipher
}

func decryptAESCBC(secret []byte, iv []byte, key []byte) []byte {
	blockSize := len(key)
	plaintext := []byte{}

	for i := 0; i < len(secret); i += blockSize {
		cipherBlock := secret[i : i+blockSize]
		plaintext = append(plaintext, calculateReapeatingXor(decryptAESECB(cipherBlock, key), iv)...)
		iv = cipherBlock
	}

	return plaintext
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

	if dataLength < padLength {
		return false
	}

	for i := 1; i < padLength-1; i++ {
		if int(data[dataLength-i]) != padLength {
			return false
		}
	}

	return true
}
