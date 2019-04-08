package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

type KeyShare struct {
	Si []byte
	N  []byte
	Id uint16
}

const HashLen = 32

type KeyShares []*KeyShare

func NewKeyShares(keyMeta *KeyMeta) (KeyShares, error) {
	if keyMeta.L <= 0 {
		return KeyShares{}, fmt.Errorf("l in KeyMeta should be greater than 0, but it is %d", keyMeta.L)
	}
	keyShares := make(KeyShares, keyMeta.L)
	var i uint16
	for i = 0; i < keyMeta.L; i++ {
		keyShares[i] = &KeyShare{}
	}
	return keyShares, nil
}

func (share KeyShare) GetIndex() uint16 {
	return share.Id - 1
}

func (share KeyShare) NodeSign(doc []byte, info *KeyMeta) (*SignatureShare, error) {
	// Init big numbers
	x := new(big.Int)
	n := new(big.Int)
	e := new(big.Int)
	si := new(big.Int)
	v := new(big.Int)
	u := new(big.Int)
	vki := new(big.Int)
	xi := new(big.Int)
	xi2 := new(big.Int)
	vPrime := new(big.Int)
	xPrime := new(big.Int)
	xTilde := new(big.Int)
	c := new(big.Int)
	z := new(big.Int)

	x.SetBytes(doc)
	n.SetBytes(info.PublicKey.N)
	e.SetBytes(info.PublicKey.E)
	si.SetBytes(share.Si)
	v.SetBytes(info.VerificationKey.V)
	u.SetBytes(info.VerificationKey.U)
	vki.SetBytes(info.VerificationKey.I[share.GetIndex()])

	nBits := n.BitLen()

	// x = doc if (doc | n) == 1 else doc * u^e
	if big.Jacobi(x, n) == -1 {
		ue := new(big.Int).Exp(u, e, n)
		x.Mul(x, ue)
		x.Mod(x, n)
	}

	// xi = x^(2*share) mod n
	xi.Mul(si, big.NewInt(2))
	xi.Exp(x, xi, n)

	// xi_2 = xi^2
	xi2.Exp(xi, big.NewInt(2), n)

	// r = abs(random(bytes_len))
	r, err := RandomDev(nBits + 2*HashLen*8)
	if err != nil {
		return &SignatureShare{}, err
	}

	// v_prime = v^r % n
	vPrime.Exp(v, r, n)

	// x_tilde = x^4 % n
	xTilde.Exp(x, big.NewInt(4), n)

	// x_prime = x_tilde^r % n
	xPrime.Exp(xTilde, r, n)

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

	hashBig := big.NewInt(0).SetBytes(hash)
	hashBig.Mod(hashBig, n)

	z.Mul(c, si)
	z.Add(z, r)

	return &SignatureShare{
		Id: share.Id,
		Xi: xi.Bytes(),
		C: c.Bytes(),
		Z: z.Bytes(),
	}, nil
}
