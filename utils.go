package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"os"
)

type cipherFunc func([]byte) []byte

// tuple is a container for a value/sort-item pair
type tuple struct {
	val        int
	measurable float64
}

// tupleSortList is s simple wrapper for a slice of distances
type tupleSortList []tuple

// Len returns the length of the distance slice to implement the sorting interface
func (l tupleSortList) Len() int { return len(l) }

// Swap switches two slice elements to implement the sorting interface
func (l tupleSortList) Swap(i int, j int) { l[i], l[j] = l[j], l[i] }

// Less compares two slice elements to implement the sorting interface
func (l tupleSortList) Less(i int, j int) bool { return l[i].measurable < l[j].measurable }

// hexToBase64 converts a string with hex encoding to one with base64 encoding
func hexToBase64(hexString string) string {
	return base64.StdEncoding.EncodeToString(hexToBytes(hexString))
}

// hexToBytes decodes a string with hex encoding and returns a byte slice for the underlying data
func hexToBytes(hexString string) []byte {
	bytes, err := hex.DecodeString(hexString)
	if err != nil {
		panic(err)
	}

	return bytes
}

// hammingDistance calculates the number of differing bits between two byte slices
func hammingDistance(a []byte, b []byte) int {
	var distance int
	for i := range a {
		distance += numberOfBitsSet(int(a[i] ^ b[i]))
	}
	return distance
}

// numberOfBitsSet calculates the number of 1 bits in an int
func numberOfBitsSet(integer int) int {
	count := 0

	for i := 1; i <= 128; i *= 2 {
		if (integer & i) > 0 {
			count++
		}
	}

	return count
}

// englishScore attempts to score how "english-like" a byte slice is
// by taking a ratio of common word characters to non-common ones
func englishScore(str []byte) float64 {
	letterCount := float64(0.1)
	nonLetterCount := float64(1)

	for _, c := range str {
		if c == ' ' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			letterCount++
		} else {
			nonLetterCount++
		}

	}

	return letterCount / nonLetterCount
}

func readBase64File(filename string) []byte {
	rawContents, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	contents, err := base64.StdEncoding.DecodeString(string(rawContents))
	if err != nil {
		panic(err)
	}

	return contents
}

func readHexSliceFile(filename string) [][]byte {
	inFile, _ := os.Open(filename)
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)

	contents := [][]byte{}
	for scanner.Scan() {
		rawContent := scanner.Text()
		content, err := hex.DecodeString(rawContent)
		if err != nil {
			panic(err)
		}

		contents = append(contents, content)
	}

	return contents
}

func randomAESCipher(message []byte, blockSize int) []byte {
	key := make([]byte, blockSize)
	fakePrepend := make([]byte, 5)
	fakeAppend := make([]byte, 5)

	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	_, err = rand.Read(fakePrepend)
	if err != nil {
		panic(err)
	}
	_, err = rand.Read(fakeAppend)
	if err != nil {
		panic(err)
	}

	newMessage := append(fakePrepend, message...)
	newMessage = append(newMessage, fakeAppend...)

	if (key[0] & 1) > 0 {
		iv := make([]byte, blockSize)
		_, err = rand.Read(iv)
		if err != nil {
			panic(err)
		}

		return encryptAESCBC(newMessage, iv, key)
	}

	return encryptAESECB(newMessage, key)
}

var unknownECBCipherKey []byte

func unknownECBCipher(message []byte) []byte {
	if unknownECBCipherKey == nil {
		unknownECBCipherKey = make([]byte, 16)
		_, err := rand.Read(unknownECBCipherKey)
		if err != nil {
			panic(err)
		}
	}

	unknownText, err := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	if err != nil {
		panic(err)
	}

	message = append(message, unknownText...)
	return encryptAESECB(message, unknownECBCipherKey)
}

func slicesAreEqual(a []byte, b []byte) bool {
	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil || len(a) != len(b) {
		return false
	}

	for j := 0; j < len(a); j++ {
		if a[j] != b[j] {
			return false
		}
	}

	return true
}
