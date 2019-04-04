package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Number of Miller-Rabin tests
const c = 25

// A random function which generates a random big number, using crypto/rand
// crypto secure Golang library.
func RandomDev(bitLen int) (*big.Int, error) {
	if bitLen <= 0 {
		return big.NewInt(0), fmt.Errorf("bitlen should be greater than 0, but it is %d", bitLen)
	}

	byteSize := bitLen / 8

	rawRand := make([]byte, byteSize)
	_, err := rand.Read(rawRand)
	if err != nil {
		return big.NewInt(0), err
	}

	return big.NewInt(0).SetBytes(rawRand), nil
}

// Returns a random prime of length bitLen, using a given random function randFn.
func randomPrime(bitLen int, randFn func(int) (*big.Int, error)) (*big.Int, error) {

	var randPrime *big.Int
	var err error

	if randFn == nil {
		return big.NewInt(0), fmt.Errorf("random function cannot be nil")
	}
	if bitLen <= 0 {
		return big.NewInt(0), fmt.Errorf("bit length must be positive")
	}

	size := bitLen

	for ok := true; ok; ok = size < bitLen {
		randPrime, err = randFn(bitLen)
		if err != nil {
			return big.NewInt(0), err
		}
		size = randPrime.BitLen()
	}

	if randPrime.BitLen() > bitLen || !randPrime.ProbablyPrime(c) {
		return big.NewInt(0), fmt.Errorf("random number returned is not prime")
	}
	return randPrime, nil
}

// Fast Safe Prime Generation.
// If it finds a prime, it tries the next probably safe prime or the previous one.
func GenerateSafePrime(bitLen int, randFn func(int) (*big.Int, error)) (*big.Int, error) {
	if randFn == nil {
		return big.NewInt(0), fmt.Errorf("random function cannot be nil")
	}
	p, err := randomPrime(bitLen, randFn)

	if err != nil {
		return big.NewInt(0), err
	}

	var ONE = big.NewInt(1)
	var TWO = big.NewInt(2)

	for true {
		q := new(big.Int)
		r := new(big.Int)

		// q is the first candidate = (p-1) / 2
		q.Quo(big.NewInt(0).Sub(p, ONE), TWO)

		// r is the second candidate = 2*(p+1)
		r.Mul(big.NewInt(0).Add(p, ONE), TWO)

		if r.ProbablyPrime(c) {
			return r, nil
		}
		if q.ProbablyPrime(c) {
			return q, nil
		}
	}

	return big.NewInt(0), fmt.Errorf("should never be here")
}
