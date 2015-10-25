package main

import (
	"bufio"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"net/url"
	"os"
)

type oracleFunc func([]byte) []byte

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

func base64ToBytes(base64str string) []byte {
	bytes, err := base64.StdEncoding.DecodeString(base64str)
	if err != nil {
		panic(err)
	}
	return bytes

}

func randomBytes(size int) []byte {
	bytes := make([]byte, size)

	_, err := crand.Read(bytes)
	if err != nil {
		panic(err)
	}

	return bytes
}

func copyBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
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

// readBase64File reads in a file by the given name and returns a byte slice of
// it's contents decoded as base64
func readBase64File(filename string) []byte {
	rawContents, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	return base64ToBytes(string(rawContents))
}

// readBase64SliceFile reads in a file by the given name and returns a slice of each line decoded as base64
func readBase64SliceFile(filename string) [][]byte {
	inFile, _ := os.Open(filename)
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)

	contents := [][]byte{}
	for scanner.Scan() {
		rawContent := scanner.Text()
		contents = append(contents, base64ToBytes(rawContent))
	}

	return contents
}

// readHexSliceFile reads in a file by the given name and returns a slice of each line decoded as hex
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

// randomAESCipher encrypts a message randomly with either ECB or CBC
func randomAESCipher(message []byte, blockSize int) []byte {
	key := randomBytes(blockSize)
	fakePrepend := randomBytes(5)
	fakeAppend := randomBytes(5)

	newMessage := append(fakePrepend, message...)
	newMessage = append(newMessage, fakeAppend...)

	if (key[0] & 1) > 0 {
		iv := randomBytes(blockSize)

		return encryptAESCBC(newMessage, iv, key)
	}

	return encryptAESECB(newMessage, key)
}

// parseQueryString takes in a query string like a=1&b=2 and returns a map[string]string
func parseQueryString(query string) map[string]string {
	v, err := url.ParseQuery(query)
	if err != nil {
		panic(err)
	}

	ourMap := map[string]string{}
	for k, vs := range v {
		if len(vs) < 1 {
			continue
		}
		ourMap[k] = vs[0]
	}

	return ourMap
}

// profileFor generates a fake user profile for an email address
func profileFor(emailAddress string) string {
	v := url.Values{
		"email": []string{emailAddress},
		"id":    []string{"10"},
		"role":  []string{"user"},
	}

	return v.Encode()
}

// encryptedProfileFor creates a user profile and encrypts it with a static key
func encryptedProfileFor(emailAddress string) []byte {
	prepareCipherOracles()
	return encryptAESECB([]byte(profileFor(emailAddress)), unknownOracleKey)
}

// prepareUserData creates a fake user data string
func prepareUserData(userData string) string {
	return "comment1=cooking%20MCs;userdata=" + url.QueryEscape(userData) + ";comment2=%20like%20a%20pound%20of%20bacon"
}

// sha1Pad should correctly pad the given message the same as the Sha1 library
func sha1Pad(message []byte) []byte {
	len := len(message)
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		message = append(message, tmp[0:56-len%64]...)
	} else {
		message = append(message, tmp[0:64+56-len%64]...)
	}

	len <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (56 - 8*i))
	}

	message = append(message, tmp[0:8]...)

	return message
}

func sha1HashToRegisters(hash []byte) [5]uint32 {
	regs := [5]uint32{}
	for i := range regs {
		regs[i] = (uint32(hash[i*4]) << 24) |
			(uint32(hash[(i*4)+1]) << 16) |
			(uint32(hash[(i*4)+2]) << 8) |
			(uint32(hash[(i*4)+3]))
	}
	return regs
}
