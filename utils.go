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
	randNum := big.NewInt(0)
	if bitLen <= 0 {
		return randNum, fmt.Errorf("bitlen should be greater than 0, but it is %d", bitLen)
	}
	byteLen := bitLen / 8
	byteRem := bitLen % 8
	if byteRem != 0 {
		byteLen++
	}
	rawRand := make([]byte, byteLen)

	for randNum.BitLen() != bitLen {
		_, err := rand.Read(rawRand)
		if err != nil {
			return randNum, err
		}
		randNum.SetBytes(rawRand)
		// set MSBs to 0 to get a bitLen equal to bitLen param.
		var bit int
		for bit = randNum.BitLen() - 1; bit >= bitLen; bit-- {
			randNum.SetBit(randNum, bit, 0)
		}
		// Set bit number (bitLen-1) to 1
		randNum.SetBit(randNum, bit, 1)
	}

	if randNum.BitLen() != bitLen {
		return big.NewInt(0), fmt.Errorf("random number returned should have length %d, but its length is %d", bitLen, randNum.BitLen())
	}

	return randNum, nil
}

// Returns a random prime of length bitLen, using a given random function randFn.
func randomPrime(bitLen int, randFn func(int) (*big.Int, error)) (*big.Int, error) {
	num := new(big.Int)
	var err error

	if randFn == nil {
		return big.NewInt(0), fmt.Errorf("random function cannot be nil")
	}
	if bitLen <= 0 {
		return big.NewInt(0), fmt.Errorf("bit length must be positive")
	}

	// Obtain a random number of length bitLen
	for num.BitLen() != bitLen {
		num, err = randFn(bitLen)
		if err != nil {
			return num, err
		}
		num = nextPrime(num, c)
	}

	if num.BitLen() != bitLen {
		return big.NewInt(0), fmt.Errorf("random number returned should have length %d, but its length is %d", bitLen, num.BitLen())
	}

	if !num.ProbablyPrime(c) {
		return big.NewInt(0), fmt.Errorf("random number returned is not prime")
	}
	return num, nil
}

// Returns the next prime number based on a specific number, checking for its primality
// using ProbablyPrime function.
func nextPrime(num *big.Int, n int) *big.Int {
	// Possible prime should be odd
	num.SetBit(num, 0, 1)
	for !num.ProbablyPrime(n) {
		// I add two to the number to obtain another odd number
		num.Add(num, big.NewInt(2))
	}
	return num
}

// Fast Safe Prime Generation. Generates two primes p and q, in a way that q
// is equal to (p-1)/2.
func GenerateSafePrimes(bitLen int, randFn func(int) (*big.Int, error)) (*big.Int, *big.Int, error) {
	if randFn == nil {
		return big.NewInt(0), big.NewInt(0), fmt.Errorf("random function cannot be nil")
	}

	q := new(big.Int)

	for true {
		p, err := randomPrime(bitLen, randFn)
		if err != nil {
			return big.NewInt(0), big.NewInt(0), err
		}
		q.Sub(p, big.NewInt(1)).Div(q, big.NewInt(2))
		if q.ProbablyPrime(c) {
			return p, q, nil
		}
	}
	return big.NewInt(0), big.NewInt(0), fmt.Errorf("should never be here")
}
