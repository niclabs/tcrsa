package tcrsa

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// SigShare represents a signature share for a document.
// It can be joined with other k signatures and generate a standard RSA signature.
type SigShare struct {
	Xi []byte // Signature share.
	C  []byte // Verification value.
	Z  []byte // Verification value
	Id uint16 // ID of the node which generated the Signature Share.
}

// Signature is the completed signature of a document, created after
// joining k signature shares.
type Signature []byte

// Verify verifies that a signature share was generated for the document provided and using a key
// related to the key metadata provided.
// It returns nil if the signature is valid, and an error if it is not.
func (sigShare SigShare) Verify(doc []byte, info *KeyMeta) error {

	x := new(big.Int)
	xi := new(big.Int)
	z := new(big.Int)
	c := new(big.Int)
	c2 := new(big.Int)
	n := new(big.Int)
	e := new(big.Int)
	v := new(big.Int)
	u := new(big.Int)
	vki := new(big.Int)
	xTilde := new(big.Int)
	xi2 := new(big.Int)
	vPrime := new(big.Int)
	xPrime := new(big.Int)

	negC := new(big.Int)
	xiNeg2c := new(big.Int)
	aux := new(big.Int)

	x.SetBytes(doc)
	n.Set(info.PublicKey.N)
	e.SetUint64(uint64(info.PublicKey.E))
	v.SetBytes(info.VerificationKey.V)
	u.SetBytes(info.VerificationKey.U)
	vki.SetBytes(info.VerificationKey.I[sigShare.Id-1])

	xi.SetBytes(sigShare.Xi)
	z.SetBytes(sigShare.Z)
	c.SetBytes(sigShare.C)

	if big.Jacobi(x, n) == -1 {
		ue := new(big.Int).Exp(u, e, n)
		x.Mul(x, ue).Mod(x, n)
	}

	// x~ = x^4 % n
	xTilde.Exp(x, big.NewInt(4), n)

	// xi_2 = xi^2 % n
	xi2.Exp(xi, big.NewInt(2), n)

	// v' = v^z * v_i^(-c)
	negC.Neg(c)
	vPrime.Exp(vki, negC, n)
	aux.Exp(v, z, n)
	vPrime.Mul(vPrime, aux).Mod(vPrime, n)

	// x' = x~^z * x_i^(-2c)
	aux.Mul(negC, big.NewInt(2))
	xiNeg2c.Exp(xi, aux, n)

	aux.Exp(xTilde, z, n)
	xPrime.Mul(aux, xiNeg2c)
	xPrime.Mod(xPrime, n)

	// Hashing all the values
	sha := sha256.New()
	sha.Write(v.Bytes())
	sha.Write(u.Bytes())
	sha.Write(xTilde.Bytes())
	sha.Write(vki.Bytes())
	sha.Write(xi2.Bytes())
	sha.Write(vPrime.Bytes())
	sha.Write(xPrime.Bytes())

	hash := sha.Sum(nil)

	c2.SetBytes(hash)
	c2.Mod(c2, n)

	if c2.Cmp(c) == 0 {
		return nil
	}
	return fmt.Errorf("invalid signature share with id %d", sigShare.Id)
}
