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


// Key Meta Args. Define the initialization values for key generation.
// Use only for testing! (Or am I being too naive believing that this is not going
// to be used in production?)
type KeyMetaArgs struct {
	E int
}

const MinBitsize = 1 << 9
const MaxBitsize = 1 << 13

// Fermat fourth number
const F4 = 65537

func GenerateKeys(bitSize int, k, l uint16, args *KeyMetaArgs) (KeyShares, *KeyMeta, error) {
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

	keyMeta := &KeyMeta{
		PublicKey:       &rsa.PublicKey{},
		K:               k,
		L:               l,
		VerificationKey: NewVerificationKey(l),
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
	lBig := new(big.Int)
	m := new(big.Int)
	n := new(big.Int)
	deltaInv := new(big.Int)
	divisor := new(big.Int)
	r := new(big.Int)
	vkv := new(big.Int)
	vku := new(big.Int)
	vki := new(big.Int)

	if p, pr, err = GenerateSafePrimes(pPrimeSize, RandomDev); err != nil {
		return make(KeyShares, 0), &KeyMeta{}, err
	}

	if q, qr, err = GenerateSafePrimes(qPrimeSize, RandomDev); err != nil {
		return make(KeyShares, 0), &KeyMeta{}, err
	}

	// n = p * q and m = p' * q'

	n.Mul(p, q)
	m.Mul(pr, qr)

	keyMeta.PublicKey.N = n

	lBig.SetUint64(uint64(l))

	eSet := false

	if args.E != 0 {
		keyMeta.PublicKey.E = args.E
		e := big.NewInt(int64(args.E))
		if e.ProbablyPrime(c) && lBig.Cmp(e) < 0 {
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
