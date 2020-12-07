package tcrsa

import (
	"fmt"
	"math/big"
)

// SigShareList is a list of sigShares ready to be joined.
type SigShareList []*SigShare

// Join generates a standard RSA signature using the signature shares of the document provided.
// The number of signatures should be at least the number of threshold defined at key creation.
// It returns the RSA signature generated, or an error if the process fails.
func (sigShareList SigShareList) Join(document []byte, info *KeyMeta) (signature Signature, err error) {
	signature = make([]byte, info.PublicKey.Size())
	if document == nil {
		err = fmt.Errorf("document is nil")
		return
	}
	if info == nil {
		err = fmt.Errorf("key metainfo is nil")
		return
	}

	if len(sigShareList) < int(info.K) {

	}

	for i := 0; i < len(sigShareList); i++ {
		if sigShareList[i] == nil {
			err = fmt.Errorf("signature share %d is nil", i)
			return
		}
	}

	k := info.K
	if len(sigShareList) < int(k) {
		err = fmt.Errorf("insufficient number of signature shares. provided: %d, needed: %d", len(sigShareList), k)
		return
	}

	x := new(big.Int)
	n := new(big.Int)
	e := new(big.Int)
	u := new(big.Int)
	delta := new(big.Int)
	ePrime := new(big.Int)
	w := new(big.Int)
	si := new(big.Int)
	aux := new(big.Int)
	a := new(big.Int)
	b := new(big.Int)
	wa := new(big.Int)
	xb := new(big.Int)
	y := new(big.Int)
	lambdaK2 := new(big.Int)

	x.SetBytes(document)
	n.Set(info.PublicKey.N)
	e.SetUint64(uint64(info.PublicKey.E))
	u.SetBytes(info.VerificationKey.U)

	// x = doc if (doc | n) == 1 else doc * u^e

	jacobied := false

	if big.Jacobi(x, n) == -1 {
		ue := new(big.Int).Exp(u, e, n)
		x.Mul(x, ue).Mod(x, n)
		jacobied = true
	} else {
	}

	delta.MulRange(1, int64(info.L))
	ePrime.SetInt64(4)

	// Calculate w
	w.SetInt64(1)

	var i uint16
	for i = 0; i < k; i++ {
		si.SetBytes(sigShareList[i].Xi)
		id := int64(sigShareList[i].Id)
		lambdaK2, err = sigShareList.lagrangeInterpolation(id, int64(k), delta)
		if err != nil {
			return
		}
		lambdaK2.Mul(lambdaK2, big.NewInt(2))
		aux.Exp(si, lambdaK2, n)
		w.Mul(w, aux)
	}

	w.Mod(w, n)

	aux.GCD(a, b, ePrime, e)
	wa.Exp(w, a, n)
	xb.Exp(x, b, n)
	y.Mul(wa, xb)

	if jacobied {
		invU := new(big.Int).ModInverse(u, n)
		y.Mul(y, invU)
	}

	y.Mod(y, n)
	sig := y.Bytes()
	// Pads sig with zeros until pk size
	copy(signature[len(signature)-len(sig):], sig)
	return
}

// This function generates the lagrange interpolation for a set of signature shares.
func (sigShareList SigShareList) lagrangeInterpolation(j, k int64, delta *big.Int) (*big.Int, error) {

	if int64(len(sigShareList)) < k {
		return new(big.Int), fmt.Errorf("signature shares are not enough. provided=%d, needed=%d", len(sigShareList), k)
	}
	out := new(big.Int)

	out.Set(delta)
	num := big.NewInt(1)
	den := big.NewInt(1)

	var i int64
	for i = 0; i < k; i++ {
		id := int64(sigShareList[i].Id)
		if id != j {
			num.Mul(num, big.NewInt(id))   // num <-- num*j_
			den.Mul(den, big.NewInt(id-j)) // den <-- den*(j_-j)
		}
	}
	out.Mul(out, num)
	out.Div(out, den)

	return out, nil
}
