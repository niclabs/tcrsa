package main

import (
	"crypto/rsa"
	"math/big"
)

// KeyMeta stores the metainformation of a distributed key generation.
// It stores the RSA public key, the threshold value k and the total shares value l.
// It also has stored the verification keys for each signed share.
type KeyMeta struct {
	PublicKey       *rsa.PublicKey
	K               uint16
	L               uint16
	VerificationKey *VerificationKey
}


// Key Meta Args. Define the initialization values for key generation.
// It allows to load previously computed keys.
type KeyMetaArgs struct {
	E int
	P *big.Int
	Q *big.Int
	R *big.Int
	U *big.Int
	FixedPoly bool
}