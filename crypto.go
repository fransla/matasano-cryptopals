package main

import (
	"crypto/aes"
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

func calculateAESECB(secret []byte, key []byte) []byte {
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
