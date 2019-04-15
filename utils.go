package tcrsa

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Number of Miller-Rabin tests
const c = 25

// randomDev is a function which generates a random big number, using crypto/rand
// crypto-secure Golang library.
func randomDev(bitLen int) (randNum *big.Int, err error) {
	randNum = big.NewInt(0)
	if bitLen <= 0 {
		err = fmt.Errorf("bitlen should be greater than 0, but it is %d", bitLen)
		return
	}
	byteLen := bitLen / 8
	byteRem := bitLen % 8
	if byteRem != 0 {
		byteLen++
	}
	rawRand := make([]byte, byteLen)

	for randNum.BitLen() != bitLen {
		_, err = rand.Read(rawRand)
		if err != nil {
			return
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
		err = fmt.Errorf("random number returned should have length %d, but its length is %d", bitLen, randNum.BitLen())
		return
	}
	return
}

// randomPrime a random prime of length bitLen, using a given random function randFn.
func randomPrime(bitLen int, randFn func(int) (*big.Int, error)) (randPrime *big.Int, err error) {
	randPrime = new(big.Int)

	if randFn == nil {
		err = fmt.Errorf("random function cannot be nil")
		return
	}
	if bitLen <= 0 {
		err = fmt.Errorf("bit length must be positive")
		return
	}

	for randPrime.BitLen() != bitLen {
		randPrime, err = randFn(bitLen)
		if err != nil {
			return
		}
		randPrime = nextPrime(randPrime, c)
	}

	if randPrime.BitLen() != bitLen {
		err = fmt.Errorf("random number returned should have length %d, but its length is %d", bitLen, randPrime.BitLen())
		return
	}

	if !randPrime.ProbablyPrime(c) {
		err = fmt.Errorf("random number returned is not prime")
		return
	}
	return
}

// nextPrime returns the next prime number based on a specific number, checking for its prime condition
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

// generateSafePrimes generates two primes p and q, in a way that q
// is equal to (p-1)/2. The greatest prime bit length is at least bitLen bits.
func generateSafePrimes(bitLen int, randFn func(int) (*big.Int, error)) (*big.Int, *big.Int, error) {
	if randFn == nil {
		return big.NewInt(0), big.NewInt(0), fmt.Errorf("random function cannot be nil")
	}

	q := new(big.Int)
	r := new(big.Int)

	for true {
		p, err := randomPrime(bitLen, randFn)
		if err != nil {
			return big.NewInt(0), big.NewInt(0), err
		}
		q.Sub(p, big.NewInt(1)).Div(q, big.NewInt(2))
		r.Mul(p, big.NewInt(2)).Add(r, big.NewInt(1))

		if q.ProbablyPrime(c) {
			return p, q, nil
		}
		if r.ProbablyPrime(c) {
			return r, p, nil
		}
	}
	return big.NewInt(0), big.NewInt(0), fmt.Errorf("should never be here")
}
