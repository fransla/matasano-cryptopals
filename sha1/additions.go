package sha1

import (
	"hash"
)

// Normally when creating or reseting the hash state we use the builtin
// magic numbers. Instead we want to be able to set these to arbitrary values
func (d *digest) ResetToGivenRegisters(registers [5]uint32) {
	for i := 0; i < 5; i++ {
		d.h[i] = registers[i]
	}

	d.nx = 0
	d.len = 0
}

// New returns a new hash.Hash computing the SHA1 checksum.
func NewWithGivenRegisters(registers [5]uint32, size uint64) hash.Hash {
	d := new(digest)
	d.FixedLength = size
	d.ResetToGivenRegisters(registers)
	return d
}
