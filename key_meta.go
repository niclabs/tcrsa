package main

import (
	"crypto/rsa"
	"fmt"
	"math/big"
)

type KeyMeta struct {
	PublicKey       *rsa.PublicKey
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
		PublicKey:       &rsa.PublicKey{},
		K:               k,
		L:               l,
		VerificationKey: NewVerificationKey(l),
	}, nil
}

func GenerateKeys(bitSize int, k, l uint16, pubE int) (KeyShares, *KeyMeta, error) {
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

	keyMeta, err := NewKeyMeta(k, l)

	if err != nil {
		return make(KeyShares, 0), &KeyMeta{}, err
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

	if p, err = GenerateSafePrime(pPrimeSize, RandomDev); err != nil {
		return make(KeyShares, 0), &KeyMeta{}, err
	}
	if q, err = GenerateSafePrime(qPrimeSize, RandomDev); err != nil {
		return make(KeyShares, 0), &KeyMeta{}, err
	}

	// p' = (p - 1) / 2
	pr.Sub(p, big.NewInt(1))
	pr.Div(pr, big.NewInt(2))

	// q' = (q - 1) / 2
	qr.Sub(q, big.NewInt(1))
	qr.Div(qr, big.NewInt(2))

	// n = p * q and m = p' * q'

	n.Mul(p, q)
	m.Mul(pr, qr)

	keyMeta.PublicKey.N = n

	ll.SetUint64(uint64(l))

	eSet := false

	if pubE <= 0 {
		keyMeta.PublicKey.E = pubE
		e := big.NewInt(int64(pubE))
		if e.ProbablyPrime(c) && ll.Cmp(e) < 0 {
			eSet = true
		}
	}
	if !eSet {
		keyMeta.PublicKey.E = F4
	}

	// d = e^{-1} mod m
	d.ModInverse(e, m)

	// generate v
	for ok := true; ok; ok = divisor.Cmp(big.NewInt(1)) != 0 {
		r, err = RandomDev(n.BitLen())
		if err != nil {
			return make(KeyShares, 0), &KeyMeta{}, nil
		}
		divisor.GCD(nil, nil, r, n)
	}
	vkv.Exp(r, big.NewInt(2), n)

	keyMeta.VerificationKey.V = vkv.Bytes()

	// generate u
	for ok := true; ok; ok = big.Jacobi(vku, n) != -1 {
		vku, err = RandomDev(n.BitLen())
		if err != nil {
			return make(KeyShares, 0), &KeyMeta{}, nil
		}
		vku.Mod(vku, n)
	}

	keyMeta.VerificationKey.U = vku.Bytes()

	// Delta is fact(l)
	deltaInv.MulRange(1, int64(l))
	deltaInv.ModInverse(deltaInv, m)

	// Generate Polynomial with random coefficients.
	poly, err := CreateRandomPolynomial(int(k-1), d, m)
	if err != nil {
		return make(KeyShares, 0), &KeyMeta{}, err
	}

	// Calculate Key Shares for each i TC participant.
	var i uint16
	for i = 1; i <= keyMeta.L; i++ {
		index := i - 1
		keyShare := keyShares[index]
		keyShare.Id = uint16(i)
		si := poly.Eval(deltaInv)
		si.Mul(si, deltaInv)
		si.Mod(si, m)
		keyShare.N = n.Bytes()

		keyShare.Si = si.Bytes()
		vki.Exp(vkv, si, n)

		keyMeta.VerificationKey.I[index] = vki.Bytes()
	}
	return keyShares, keyMeta, nil
}
