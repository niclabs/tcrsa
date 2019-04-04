package main

type VerificationKey struct{
	V []byte
	U []byte
	I [][]byte
}


func NewVerificationKey(l uint16) *VerificationKey {
	vk := &VerificationKey{
		I: make([][]byte, l),
	}
	return vk
}