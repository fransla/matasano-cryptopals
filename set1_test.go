package main

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChallenge1(t *testing.T) {
	hex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	base64 := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	assert.Equal(t, base64, hexToBase64(hex))
}

func TestChallenge2(t *testing.T) {
	a := hexToBytes("1c0111001f010100061a024b53535009181c")
	b := hexToBytes("686974207468652062756c6c277320657965")
	c := hexToBytes("746865206b696420646f6e277420706c6179")

	assert.Equal(t, c, calculateXor(a, b))
}

func TestChallenge3(t *testing.T) {
	secret := hexToBytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

	key, message := crackSingleByteXor(secret)

	assert.Equal(t, 'X', key)
	assert.Equal(t, "Cooking MC's like a pound of bacon", message)
}

func TestChallenge4(t *testing.T) {
	challenges := readHexSliceFile("data/4.txt")

	// Crack each string in the file as a single byte xor cipher and find the most English-like
	var winner []byte
	var maxScore float64
	for _, challenge := range challenges {
		_, message := crackSingleByteXor(challenge)
		score := englishScore(message)
		if score > maxScore {
			winner = message
			maxScore = score
		}
	}

	assert.Equal(t, []byte("Now that the party is jumping\n"), winner)
}

func TestChallenge5(t *testing.T) {
	text := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")
	expectedCipher := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	assert.Equal(t, expectedCipher, hex.EncodeToString(calculateXor(text, key)))
}

func TestChallenge6(t *testing.T) {
	secret := readBase64File("data/6.txt")

	key, message := crackRepeatingKeyXor(secret)

	assert.Equal(t, "Terminator X: Bring the noise", key)
	assert.Equal(t, []byte("I'm back and I'm"), message[0:16])
}

func TestChallenge7(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	secret := readBase64File("data/7.txt")

	message := decryptAESECB(secret, key)

	assert.Equal(t, []byte("I'm back and I'm"), message[0:16])
}

func TestChallenge8(t *testing.T) {
	challenges := readHexSliceFile("data/8.txt")
	blockSize := 16

	var ecbLineNo int
	for lineNo, challenge := range challenges {
		if isAESECB(challenge, blockSize) {
			ecbLineNo = lineNo
			break
		}
	}

	assert.Equal(t, 132, ecbLineNo)
}
