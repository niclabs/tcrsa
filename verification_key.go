package main

// VerificationKey represents the data that is needed to verify a Key Share.
// It groups all the verification values for all the nodes in I property.
type VerificationKey struct {
	V []byte
	U []byte
	I [][]byte
}

// NewVerificationKey generates an empty Verification Key structure, allocating
// space for l verification values in I.
func NewVerificationKey(l uint16) *VerificationKey {
	vk := &VerificationKey{
		I: make([][]byte, l),
	}
	return vk
}
