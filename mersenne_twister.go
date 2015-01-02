package main

import (
	"errors"
	"time"
)

const mersenneTwisterStateLength = 624

type mersenneTwister struct {
	state []int
	index int
}

func newMersenneTwister(seed int) *mersenneTwister {
	mt := &mersenneTwister{state: make([]int, 0, mersenneTwisterStateLength)}

	mt.state = append(mt.state, seed)
	for i := 1; i < mersenneTwisterStateLength; i++ {
		prev := mt.state[i-1]
		mt.state = append(mt.state, int(int32(0x6c078965*(prev^(prev>>30))+i))&0x7fffffff)
	}

	return mt
}

func (mt *mersenneTwister) next() int {
	if mt.index == 0 {
		for i := 0; i < mersenneTwisterStateLength; i++ {
			next := mt.state[(i+1)%mersenneTwisterStateLength]
			y := (mt.state[i] & 0x80000000) + (next & 0x7fffffff)
			mt.state[i] = mt.state[(i+397)%mersenneTwisterStateLength] ^ (y >> 1)
			if (y % 2) != 0 {
				mt.state[i] = mt.state[i] ^ 0x9908b0df
			}
		}
	}

	y := temperMersenneTwisterNumber(mt.state[mt.index])
	mt.index = (mt.index + 1) % mersenneTwisterStateLength

	return y
}

func temperMersenneTwisterNumber(y int) int {
	y ^= y >> 11                // 1st step
	y ^= (y << 7) & 0x9d2c5680  // 2nd step
	y ^= (y << 15) & 0xefc60000 // 3rd step
	y ^= y >> 18                // 4th step
	return y
}

func untemperMersenneTwisterNumber(y int) int {
	// Undo 4th step
	y ^= y >> 18

	// Undo 3rd step
	y ^= (y << 15) & 0xefc60000

	// Undo 2nd step
	x := y
	x = y ^ (x<<7)&0x9d2c5680
	x = y ^ (x<<7)&0x9d2c5680
	x = y ^ (x<<7)&0x9d2c5680
	x = y ^ (x<<7)&0x9d2c5680

	// Undo 1st step
	z := x
	z = x ^ (z >> 11)
	z = x ^ (z >> 11)

	return z
}

func crackMersenneTwisterSeed(mt *mersenneTwister) (int, error) {
	target := mt.next()

	currentTimestamp := int(time.Now().Unix())
	for i := currentTimestamp; i >= currentTimestamp-300; i-- {
		testMt := newMersenneTwister(i)
		if testMt.next() == target {
			return i, nil
		}
	}

	return 0, errors.New("Could not determine seed")
}
