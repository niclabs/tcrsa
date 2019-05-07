// This library implements the cryptographic algorithms of Victor Shoup's paper Practical Threshold Signatures, in the Golang programming language.
// You can find the paper defining the algorithms in http://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf.
package tcrsa

import (
	"crypto/rsa"
	"fmt"
	"math/big"
)

// Minimum bit size for the key generation: 512 bits.
const minBitSize = 1 << 9

// Maximum bit size for the key generation: 4096 bits.
const maxBitSize = 1 << 13

// Fermat fourth number
// Default e value.
const f4 = 65537

// NewKey creates l key shares for a k-threshold signing scheme.
// The bit_size parameter is used to generate key shares with a security level equivalent to a RSA private of that size.
// The generated key shares have a threshold parameter of k. This means that k valid signatures are needed to sign.
// On success, it returns the meta information common to all the keys, and an array with all the key shares.
// On failure, it returns an error and invalid pointers to shares and meta information.
func NewKey(bitSize int, k, l uint16, args *KeyMetaArgs) (shares KeyShareList, meta *KeyMeta, err error) {

	if args == nil {
		args = &KeyMetaArgs{}
	}

	// Parameter checking
	if bitSize < minBitSize || bitSize > maxBitSize {
		err = fmt.Errorf("bit size should be between %d and %d, but it is %d", minBitSize, maxBitSize, bitSize)
		return
	}
	if l <= 1 {
		err = fmt.Errorf("l should be greater than 1, but it is %d", l)
		return
	}
	if k <= 0 {
		err = fmt.Errorf("k should be greater than 0, but it is %d", k)
		return
	}
	if k < (l/2+1) || k > l {
		err = fmt.Errorf("k should be between the %d and %d, but it is %d", (l/2)+1, l, k)
		return
	}

	pPrimeSize := (bitSize + 1) / 2
	qPrimeSize := bitSize - pPrimeSize - 1

	if args.P != nil && args.P.BitLen() != pPrimeSize {
		err = fmt.Errorf("P bit length is %d, but it should be %d", args.P.BitLen(), pPrimeSize)
		return
	}
	if args.Q != nil && args.Q.BitLen() != qPrimeSize {
		err = fmt.Errorf("Q bit length is %d, but it should be %d", args.Q.BitLen(), qPrimeSize)
		return
	}

	meta = &KeyMeta{
		PublicKey:       &rsa.PublicKey{},
		K:               k,
		L:               l,
		VerificationKey: NewVerificationKey(l),
	}
	shares = make(KeyShareList, meta.L)

	var i uint16
	for i = 0; i < meta.L; i++ {
		shares[i] = &KeyShare{}
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
		if !args.P.ProbablyPrime(c) {
			err = fmt.Errorf("p should be prime, but it's not")
			return
		}
		p.Set(args.P)
		pr.Sub(p, big.NewInt(1)).Div(pr, big.NewInt(2))
	} else {
		if p, pr, err = generateSafePrimes(pPrimeSize, randomDev); err != nil {
			return
		}
	}

	if args.Q != nil {
		if !args.Q.ProbablyPrime(c) {
			err = fmt.Errorf("q should be prime, but it's not")
			return
		}
		q.Set(args.Q)
		qr.Sub(q, big.NewInt(1)).Div(qr, big.NewInt(2))
	} else {
		if q, qr, err = generateSafePrimes(qPrimeSize, randomDev); err != nil {
			return
		}
	}

	// n = p * q and m = p' * q'
	n.Mul(p, q)
	m.Mul(pr, qr)

	meta.PublicKey.N = n

	lBig.SetUint64(uint64(l))

	eSet := false

	if args.E != 0 {
		meta.PublicKey.E = args.E
		e = big.NewInt(int64(meta.PublicKey.E))
		if e.ProbablyPrime(c) && lBig.Cmp(e) < 0 {
			eSet = true
		}
	}
	if !eSet {
		meta.PublicKey.E = f4
		e = big.NewInt(int64(meta.PublicKey.E))
	}

	// d = e^{-1} mod m
	d.ModInverse(e, m)

	// generate v
	if args.R == nil {
		for divisor.Cmp(big.NewInt(1)) != 0 {
			r, err = randomDev(n.BitLen())
			if err != nil {
				return
			}
			divisor.GCD(nil, nil, r, n)
		}
	} else {
		divisor.GCD(nil, nil, args.R, n)
		if divisor.Cmp(big.NewInt(1)) != 0 {
			err = fmt.Errorf("provided r value should be coprime with p*q (i.e., it should not be 0, 1, p or q)")
			return
		}
		r.Set(args.R)
	}

	vkv.Exp(r, big.NewInt(2), n)

	meta.VerificationKey.V = vkv.Bytes()

	// generate u
	if args.U == nil {
		for cond := true; cond; cond = big.Jacobi(vku, n) != -1 {
			vku, err = randomDev(n.BitLen())
			if err != nil {
				return
			}
			vku.Mod(vku, n)
		}
	} else {
		vku.Set(args.U)
	}

	meta.VerificationKey.U = vku.Bytes()

	// Delta is fact(l)
	deltaInv.MulRange(1, int64(l)).ModInverse(deltaInv, m)

	// Generate polynomial with random coefficients.
	var poly polynomial
	poly, err = createRandomPolynomial(int(k-1), d, m)

	if err != nil {
		return
	}

	// Calculate Key Shares for each i TC participant.
	for i = 1; i <= meta.L; i++ {
		keyShare := shares[i-1]
		keyShare.Id = i
		si := poly.eval(big.NewInt(int64(i)))
		si.Mul(si, deltaInv)
		si.Mod(si, m)
		keyShare.Si = si.Bytes()
		vki.Exp(vkv, si, n)

		meta.VerificationKey.I[i-1] = vki.Bytes()
	}
	return
}
