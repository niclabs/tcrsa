package tcrsa

import (
	"math/big"
	"testing"
)

func TestSignatureShareList_LagrangeInterpolation(t *testing.T) {
	const signatureShareTestLength = 5
	const signatureShareTestK = 5
	const signatureShareTestM = 1024

	delta := new(big.Int)

	shares := make(SigShareList, signatureShareTestLength)

	var i uint16
	for i = 0; i < signatureShareTestLength; i++ {
		shares[i] = &SigShare{
			Id: i + 1,
		}
	}
	delta.MulRange(1, signatureShareTestK)

	results := []*big.Int{
		big.NewInt(600),
		big.NewInt(-1200),
		big.NewInt(1200),
		big.NewInt(-600),
		big.NewInt(120),
	}

	for i := 0; i < signatureShareTestK; i++ {
		res, err := shares.lagrangeInterpolation(int64(i+1), signatureShareTestK, delta)
		if err != nil {
			t.Errorf("couldn't compute lagrange interpolation")
			return
		}
		if res.Cmp(results[i]) != 0 {
			t.Errorf("lagrange interpolation for i=%d failed. It is %s but it should be %s", i+1, res, results[i])
		}
	}

}
