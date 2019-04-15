package tcrsa

import (
	"crypto/rsa"
	"math/big"
)

// KeyMeta stores the meta information of a distributed key generation.
// It stores the RSA public key, the threshold value k and the total shares value l.
// It also has stored the verification keys for each signed share.
type KeyMeta struct {
	PublicKey       *rsa.PublicKey   // RSA Public key used to verify signatures
	K               uint16           // Threshold
	L               uint16           // Total number of participants
	VerificationKey *VerificationKey // Verification Key associated to a Key Generation.
}

// KeyMetaArgs defines the initialization values for key generation.
// It allows to load previously computed keys. Useful for testing. Completely forbidden for
// production use.
type KeyMetaArgs struct {
	E int      // Public exponent. This value should be prime.
	P *big.Int // A prime, it should have the half of the bitsize.
	Q *big.Int // Another prime, it should have the other half of the bitsize.
	R *big.Int // A random prime but it must be coprime with P*Q.
	U *big.Int // An arbitrary random value.
}
