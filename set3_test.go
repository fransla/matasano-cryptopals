package main

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestChallenge17(t *testing.T) {
	iv := []byte("YELLOW SUBMARINE")

	plaintextsFingerprints := map[string]struct{}{}

	// Oracle gives a random cipher so run a bunch of times so we hopefully get them all
	for i := 0; i < 50; i++ {
		cipher := cbcPaddingOracle(iv)

		for j := 0; j < 10; j++ {
			plaintext, err := crackCBCWithPaddingOracle(cipher, iv)
			if err == nil {
				// Remember we've seen this plaintext
				plaintextsFingerprints[string(plaintext[0:6])] = struct{}{}
				break
			}
		}
	}

	// Ensure we've seen them all
	assert.Equal(t, 10, len(plaintextsFingerprints))
}

func TestChallenge18(t *testing.T) {
	cipher := base64ToBytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	key := []byte("YELLOW SUBMARINE")
	nonce := make([]byte, 8)

	plaintext := calculateAESCTR(cipher, key, nonce)
	assert.Equal(t, "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ", string(plaintext))

	key = []byte("WOWMANYSECRECY!!")
	plaintext = []byte("Hey this stream cipher stuff is p cool")
	assert.Equal(t, plaintext, calculateAESCTR(calculateAESCTR(plaintext, key, nonce), key, nonce))

}

func TestChallenge19(t *testing.T) {
	// TODO
}

func TestChallenge20(t *testing.T) {
	messages := readBase64SliceFile("data/20.txt")
	key := []byte("YELLOW SUBMARINE")
	nonce := make([]byte, 8)

	var shortestCipher int
	ciphers := make([][]byte, 0, len(messages))

	for _, message := range messages {
		cipher := calculateAESCTR(message, key, nonce)
		ciphers = append(ciphers, cipher)

		cipherLength := len(cipher)
		if shortestCipher == 0 || cipherLength < shortestCipher {
			shortestCipher = cipherLength
		}
	}

	concatenatedCiphers := make([]byte, 0, len(ciphers)*shortestCipher)
	for _, cipher := range ciphers {
		concatenatedCiphers = append(concatenatedCiphers, cipher[0:shortestCipher]...)
	}

	_, message := crackRepeatingKeyXor(concatenatedCiphers, []int{shortestCipher})

	assert.Equal(t, string(message[0:13]), "i'm rated \"R\"")
}

func TestChallenge21(t *testing.T) {
	randomSeed := rand.Intn(99999)
	mt1 := newMersenneTwister(randomSeed)
	mt2 := newMersenneTwister(randomSeed)

	for i := 0; i < 100; i++ {
		assert.Equal(t, mt1.next(), mt2.next())
	}
}

func TestChallenge22(t *testing.T) {
	seed := int(time.Now().Unix())
	crackedSeed, err := crackMersenneTwisterSeed(newMersenneTwister(seed))
	assert.NoError(t, err)
	assert.Equal(t, seed, crackedSeed)
}
