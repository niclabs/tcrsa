package tcrsa

// VerificationKey represents the data that is needed to verify a Key Share.
// It groups all the verification values for all the nodes in I property.
type VerificationKey struct {
	V []byte   // Verification value.
	U []byte   // Verification value.
	I [][]byte // An array of the verification values for the shares the nodes create when sign a document.
}

// NewVerificationKey generates an empty Verification Key structure, allocating
// space for l verification values in I.
func NewVerificationKey(l uint16) *VerificationKey {
	vk := &VerificationKey{
		I: make([][]byte, l),
	}
	return vk
}
