package main

import (
	"testing"

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
