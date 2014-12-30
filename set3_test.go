package main

import (
	"fmt"
	"testing"
)

func TestChallenge17(t *testing.T) {
	iv := []byte("YELLOW SUBMARINE")

	for i := 0; i < 20; i++ {
		cipher := cbcPaddingOracle(iv)
		fmt.Println(string(crackCBCWithPaddingOracle(cipher, iv)))
	}
}
