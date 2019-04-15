package main

import (
	"crypto/rsa"
	"fmt"
	"math/big"
)

const MinBitsize = 1 << 9
const MaxBitsize = 1 << 13

// Fermat fourth number
// Default e value.
const F4 = 65537

// This function creates l key shares for a k-threshold signing scheme.
// It returns the meta information common to all the keys, and an array with all the key shares.
func GenerateKeys(bitSize int, k, l uint16, args *KeyMetaArgs) (keyShares KeyShares, keyMeta *KeyMeta, err error) {

	// Parameter checking
	if bitSize < MinBitsize || bitSize > MaxBitsize {
		return make(KeyShares, 0), &KeyMeta{}, fmt.Errorf("bit size should be between %d and %d, but it is %d", MinBitsize, MaxBitsize, bitSize)
	}
	if l <= 1 {
		return make(KeyShares, 0), &KeyMeta{}, fmt.Errorf("l should be greater than 1, but it is %d", l)
	}
	if k <= 0 {
		return make(KeyShares, 0), &KeyMeta{}, fmt.Errorf("k should be greater than 0, but it is %d", k)
	}
	if k < (l/2+1) || k > l {
		return make(KeyShares, 0), &KeyMeta{}, fmt.Errorf("k should be between the %d and %d, but it is %d", (l/2)+1, l, k)
	}

	pPrimeSize := (bitSize + 1) / 2
	qPrimeSize := bitSize - pPrimeSize - 1

	if args.P != nil && args.P.BitLen() != pPrimeSize {
		return make(KeyShares, 0), &KeyMeta{}, fmt.Errorf("P bit length is %d, but it should be %d", args.P.BitLen(), pPrimeSize)
	}
	if args.Q != nil && args.Q.BitLen() != qPrimeSize {
		return make(KeyShares, 0), &KeyMeta{}, fmt.Errorf("Q bit length is %d, but it should be %d", args.Q.BitLen(), qPrimeSize)
	}

	keyMeta = &KeyMeta{
		PublicKey:       &rsa.PublicKey{},
		K:               k,
		L:               l,
		VerificationKey: NewVerificationKey(l),
	}

	keyShares = make(KeyShares, keyMeta.L)

	var i uint16
	for i = 0; i < keyMeta.L; i++ {
		keyShares[i] = &KeyShare{}
	}

	// Init big numbers
	pr := new(big.Int)
	qr := new(big.Int)
	p := new(big.Int)
	q := new(big.Int)
	d := new(big.Int)
	e := new(big.Int)
	lBig := new(big.Int)
	m := new(big.Int)
	n := new(big.Int)
	deltaInv := new(big.Int)
	divisor := new(big.Int)
	r := new(big.Int)
	vkv := new(big.Int)
	vku := new(big.Int)
	vki := new(big.Int)

	if args.P != nil {
		p.Set(args.P)
		pr.Sub(p, big.NewInt(1)).Div(pr, big.NewInt(2))
	} else {
		if p, pr, err = GenerateSafePrimes(pPrimeSize, RandomDev); err != nil {
			return make(KeyShares, 0), &KeyMeta{}, err
		}
	}

	if args.Q != nil {
		q.Set(args.Q)
		qr.Sub(q, big.NewInt(1)).Div(qr, big.NewInt(2))
	} else {
		if q, qr, err = GenerateSafePrimes(qPrimeSize, RandomDev); err != nil {
			return make(KeyShares, 0), &KeyMeta{}, err
		}
	}

	// n = p * q and m = p' * q'
	n.Mul(p, q)
	m.Mul(pr, qr)

	keyMeta.PublicKey.N = n

	lBig.SetUint64(uint64(l))

	eSet := false

	if args.E != 0 {
		keyMeta.PublicKey.E = args.E
		e = big.NewInt(int64(keyMeta.PublicKey.E))
		if e.ProbablyPrime(c) && lBig.Cmp(e) < 0 {
			eSet = true
		}
	}
	if !eSet {
		keyMeta.PublicKey.E = F4
		e = big.NewInt(int64(keyMeta.PublicKey.E))
	}

	// d = e^{-1} mod m
	d.ModInverse(e, m)

	// generate v

	if args.R == nil {
		for divisor.Cmp(big.NewInt(1)) != 0 {
			r, err = RandomDev(n.BitLen())
			if err != nil {
				return make(KeyShares, 0), &KeyMeta{}, nil
			}
			divisor.GCD(nil, nil, r, n)
		}
	} else {
		r.Set(args.R)
	}

	vkv.Exp(r, big.NewInt(2), n)

	keyMeta.VerificationKey.V = vkv.Bytes()

	// generate u

	if args.U == nil {
		for cond := true; cond; cond = big.Jacobi(vku, n) != -1 {
			vku, err = RandomDev(n.BitLen())
			if err != nil {
				return make(KeyShares, 0), &KeyMeta{}, nil
			}
			vku.Mod(vku, n)
		}
	} else {
		vku.Set(args.U)
	}

	keyMeta.VerificationKey.U = vku.Bytes()

	// Delta is fact(l)
	deltaInv.MulRange(1, int64(l)).ModInverse(deltaInv, m)

	// Generate Polynomial with random coefficients.

	var poly Polynomial

	if !args.FixedPoly {
		poly, err = CreateRandomPolynomial(int(k-1), d, m)
	} else {
		poly, err = CreateFixedPolynomial(int(k-1), d, m)
	}
	if err != nil {
		return make(KeyShares, 0), &KeyMeta{}, err
	}

	// Calculate Key Shares for each i TC participant.
	for i = 1; i <= keyMeta.L; i++ {
		keyShare := keyShares[i-1]
		keyShare.Id = i
		si := poly.Eval(big.NewInt(int64(i)))
		si.Mul(si, deltaInv)
		si.Mod(si, m)
		keyShare.N = n.Bytes()

		keyShare.Si = si.Bytes()
		vki.Exp(vkv, si, n)

		keyMeta.VerificationKey.I[i-1] = vki.Bytes()
	}
	return keyShares, keyMeta, nil
}
