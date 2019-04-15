package tcrsa

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
)

// KeyShare stores the Si value of a node and an unique incremental ID for the node.
// It's used to generate a signature share.
type KeyShare struct {
	Si []byte // S_i value of the Key Share.
	Id uint16 // ID of the key share.
}

// KeyShareList is a list of KeyShare values.
type KeyShareList []*KeyShare

// EqualsSi compares two key share S_i values and returns true if they are equal.
func (keyShare KeyShare) EqualsSi(keyShare2 *KeyShare) bool {
	if keyShare2 == nil {
		return false
	}
	return bytes.Compare(keyShare.Si, keyShare2.Si) == 0
}

// ToBase64 transforms a Si value of a keyshare to Base64, and returns it.
func (keyShare KeyShare) ToBase64() string {
	return base64.StdEncoding.EncodeToString(keyShare.Si)
}

// Sign generates a signature share using a key share. A standard RSA signature is generated using several
// signature shares. The document to be signed should be prepared (hashed and padded) before using this function.
// It returns a SigShare with the signature of this node, or an error if the signing process failed.
func (keyShare KeyShare) Sign(doc []byte, hashType crypto.Hash, info *KeyMeta) (sigShare *SigShare, err error) {

	x := new(big.Int)
	xi := new(big.Int)
	z := new(big.Int)
	c := new(big.Int)
	n := new(big.Int)
	e := new(big.Int)
	v := new(big.Int)
	u := new(big.Int)
	vki := new(big.Int)
	xTilde := new(big.Int)
	xi2 := new(big.Int)
	vPrime := new(big.Int)
	xPrime := new(big.Int)
	exp := new(big.Int)
	si := new(big.Int)

	x.SetBytes(doc)
	n.Set(info.PublicKey.N)
	e.SetUint64(uint64(info.PublicKey.E))
	v.SetBytes(info.VerificationKey.V)
	u.SetBytes(info.VerificationKey.U)
	vki.SetBytes(info.VerificationKey.I[keyShare.Id-1])

	si.SetBytes(keyShare.Si)

	// x = doc if (doc | n) == 1 else doc * u^e
	if big.Jacobi(x, n) == -1 {
		ue := new(big.Int).Exp(u, e, n)
		x.Mul(x, ue).Mod(x, n)
	}
	// xi = x^(2*keyShare) mod n
	exp.Mul(si, big.NewInt(2))
	xi.Exp(x, exp, n)
	// x~ = x^4 % n
	xTilde.Exp(x, big.NewInt(4), n)

	// xi2 = xi^2 % n
	xi2.Exp(xi, big.NewInt(2), n)

	// r = abs(random(bytes_len))
	r, err := randomDev(n.BitLen() + 2*hashType.Size()*8)
	if err != nil {
		return
	}

	// v' = v^r % n
	vPrime.Exp(v, r, n)

	// x' = x~^r % n
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

	c.SetBytes(hash)
	c.Mod(c, n)

	z.Mul(c, si)
	z.Add(z, r)

	sigShare = &SigShare{
		Id: keyShare.Id,
		Xi: xi.Bytes(),
		C:  c.Bytes(),
		Z:  z.Bytes(),
	}
	return
}
