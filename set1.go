package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
)

// Set1Challenge1 performs Matasano crypto challenge #1
func Set1Challenge1() {
	fmt.Println(hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
}

// Set1Challenge2 performs Matasano crypto challenge #2
func Set1Challenge2() {
	a := hexToBytes("1c0111001f010100061a024b53535009181c")
	b := hexToBytes("686974207468652062756c6c277320657965")

	fmt.Println(hex.EncodeToString(calculateReapeatingXor(a, b)))
}

// Set1Challenge3 performs Matasano crypto challenge #3
func Set1Challenge3() {
	secret := hexToBytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

	key, message := crackSingleByteXor(secret)

	fmt.Println("Key is:", string(key))
	fmt.Println("Message is:")
	fmt.Println(string(message))
}

// Set1Challenge4 performs Matasano crypto challenge #4
func Set1Challenge4() {
	inFile, _ := os.Open("4.txt")
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)

	challenges := [][]byte{}
	for scanner.Scan() {
		rawChallenge := scanner.Text()
		challenge, err := hex.DecodeString(rawChallenge)
		if err != nil {
			panic(err)
		}

		challenges = append(challenges, challenge)
	}

	var winner []byte
	var maxScore float64

	for _, challenge := range challenges {
		for i := 0; i < 255; i++ {
			attempt := calculateSingleByteXor(challenge, byte(i))
			score := englishScore([]byte(attempt))

			if score > maxScore {
				maxScore = score
				winner = attempt
			}

		}
	}

	fmt.Println(string(winner))
}

// Set1Challenge5 performs Matasano crypto challenge #5
func Set1Challenge5() {
	text := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")

	fmt.Println(hex.EncodeToString(calculateReapeatingXor(text, key)))
}

// Set1Challenge6 performs Matasano crypto challenge #6
func Set1Challenge6() {
	rawSecret, err := ioutil.ReadFile("6.txt")
	if err != nil {
		panic(err)
	}

	secret, err := base64.StdEncoding.DecodeString(string(rawSecret))
	if err != nil {
		panic(err)
	}

	key, message := crackRepeatingKeyXor(secret)

	fmt.Println("Key probably is:", string(key))
	fmt.Println("Message probably is:", string(message))
}
