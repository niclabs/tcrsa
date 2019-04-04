package main

import (
	"fmt"
	"math/big"
)

type KeyMeta struct {
	PublicKey       *PublicKey
	K               uint16
	L               uint16
	VerificationKey *VerificationKey
}

const MinBitsize = 1 << 9
const MaxBitsize = 1 << 13

// Fermat fourth number
const F4 = 65537

func NewKeyMeta(k, l uint16) (*KeyMeta, error) {
	if l <= 1 {
		return &KeyMeta{}, fmt.Errorf("l should be greater than 1, but it is %d", l)
	}
	if k <= 0 {
		return &KeyMeta{}, fmt.Errorf("k should be greater than 0, but it is %d", k)
	}
	if k < (l/2+1) || k > l {
		return &KeyMeta{}, fmt.Errorf("k should be between the %d and %d, but it is %d", (l/2)+1, l, k)
	}
	return &KeyMeta{
		PublicKey:       &PublicKey{},
		K:               k,
		L:               l,
		VerificationKey: NewVerificationKey(l),
	}, nil
}

func GenerateKeys(bitSize int, k, l uint16, pubE []byte) (*KeyMeta, error) {
	if bitSize < MinBitsize || bitSize > MaxBitsize {
		return &KeyMeta{}, fmt.Errorf("bit size should be between %d and %d, but it is %d", MinBitsize, MaxBitsize, bitSize)
	}
	if l <= 1 {
		return &KeyMeta{}, fmt.Errorf("l should be greater than 1, but it is %d", l)
	}
	if k <= 0 {
		return &KeyMeta{}, fmt.Errorf("k should be greater than 0, but it is %d", k)
	}
	if k < (l/2+1) || k > l {
		return &KeyMeta{}, fmt.Errorf("k should be between the %d and %d, but it is %d", (l/2)+1, l, k)
	}

	keyMeta, err := NewKeyMeta(k, l)

	if err != nil {
		return &KeyMeta{}, err
	}

	keyShares, err := NewKeyShares(keyMeta)

	pPrimeSize := (bitSize + 1) / 2
	qPrimeSize := bitSize - pPrimeSize - 1

	// Init big numbers
	pr := new(big.Int)
	qr := new(big.Int)
	p := new(big.Int)
	q := new(big.Int)
	d := new(big.Int)
	e := new(big.Int)
	ll := new(big.Int)
	m := new(big.Int)
	n := new(big.Int)
	deltaInv := new(big.Int)
	divisor := new(big.Int)
	r := new(big.Int)
	vkv := new(big.Int)
	vku := new(big.Int)
	vki := new(big.Int)

	// Common use big numbers

	var ONE = big.NewInt(1)
	var TWO = big.NewInt(2)

	if p, err = GenerateSafePrime(pPrimeSize, RandomDev); err != nil {
		return &KeyMeta{}, err
	}
	if q, err = GenerateSafePrime(qPrimeSize, RandomDev); err != nil {
		return &KeyMeta{}, err
	}

	// p' = (p - 1) / 2
	pr.Sub(p, ONE)
	pr.Div(pr, TWO)

	// q' = (q - 1) / 2
	qr.Sub(q, ONE)
	qr.Div(qr, TWO)

	// n = p * q and m = p' * q'

	n.Mul(p, q)
	m.Mul(pr, qr)

	nEncoded, err := n.GobEncode()
	if err != nil {
		return &KeyMeta{}, err
	}
	keyMeta.PublicKey.N = nEncoded

	ll.SetUint64(uint64(l))

	eSet := false

	if pubE != nil {
		e.SetBytes(pubE)
		if e.ProbablyPrime(c) && ll.Cmp(e) < 0 {
			eSet = true
		}
	}
	if !eSet {
		e.SetUint64(F4) // l is always less than 65537 (l is an uint16_t)
	}

	exp, err := e.GobEncode()
	if err != nil {
		return &KeyMeta{}, err
	}
	keyMeta.PublicKey.E = exp

	// d = e^{-1} mod m
	d.ModInverse(e, m)

	// generate v
	for ok := true; ok; ok = divisor.Cmp(ONE) != 0 {
		r, err = RandomDev(n.BitLen())
		if err != nil {
			return &KeyMeta{}, nil
		}
		divisor.GCD(r, n, nil, nil)
	}
	vkv.Exp(r, TWO, n)

	vkVEncoded, err := vkv.GobEncode()
	if err != nil {
		return &KeyMeta{}, err
	}
	keyMeta.VerificationKey.V = vkVEncoded

	// generate u
	for ok := true; ok; ok = big.Jacobi(vku, n) != -1 {
		vku, err = RandomDev(n.BitLen())
		if err != nil {
			return &KeyMeta{}, nil
		}
		vku.Mod(vku, n)
	}

	vkUEncoded, err := vku.GobEncode()
	if err != nil {
		return &KeyMeta{}, err
	}
	keyMeta.VerificationKey.U = vkUEncoded

	// Delta is fact(l)
	deltaInv.MulRange(1, int64(l))
	deltaInv.ModInverse(deltaInv, m)

	// Generate Polynomial with random coefficients.
	poly, err := CreateRandomPolynomial(int(k-1), d, m)
	if err != nil {
		return &KeyMeta{}, err
	}

	// Calculate Key Shares for each i TC participant.
	var i uint16
	for i = 1; i < keyMeta.L; i++ {
		index := i - 1
		keyShare := keyShares[index]
		keyShare.Id = i
		si := poly.Eval(deltaInv)
		si.Mul(si, deltaInv)
		si.Mod(si, m)
		keyShare.N = nEncoded

		siEncoded, err := si.GobEncode()
		if err != nil {
			return &KeyMeta{}, err
		}
		keyShare.Si = siEncoded
		vki.Exp(vkv, si, n)

		vkiEncoded, err := vki.GobEncode()
		if err != nil {
			return &KeyMeta{}, err
		}
		keyMeta.VerificationKey.I[index] = vkiEncoded
	}
	return keyMeta, nil
}
