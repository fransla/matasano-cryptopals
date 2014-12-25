package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"os"
)

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

func hexToBase64(hexString string) string {
	return base64.StdEncoding.EncodeToString(hexToBytes(hexString))
}

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
