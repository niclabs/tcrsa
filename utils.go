package tcrsa

import (
	"crypto/rand"
	mathRand "math/rand"
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
	if bitLen % 8 != 0 {
		byteLen++
	}
	rawRand := make([]byte, byteLen)

	for randNum.BitLen() == 0 || randNum.BitLen() > bitLen {
		_, err = rand.Read(rawRand)
		if err != nil {
			return
		}
		randNum.SetBytes(rawRand)
		// set MSBs to 0 to get a bitLen equal to bitLen param.
		for bit := bitLen; bit < randNum.BitLen(); bit++ {
			randNum.SetBit(randNum, bit, 0)
		}
	}

	if randNum.BitLen() == 0 || randNum.BitLen() > bitLen {
		err = fmt.Errorf("random number returned should have length at most %d, but its length is %d", bitLen, randNum.BitLen())
		return
	}
	return
}

// randomFixed returns a seeded pseudorandom function that returns a random number of bitLen bits.
func randomFixed(seed int64) func(int) (*big.Int, error) {
	seededRand := mathRand.New(mathRand.NewSource(seed))
	return func(bitLen int) (randNum *big.Int, err error) {
		randNum = big.NewInt(0)
		if bitLen <= 0 {
			err = fmt.Errorf("bitlen should be greater than 0, but it is %d", bitLen)
			return
		}
		byteLen := bitLen / 8
		if bitLen % 8 != 0 {
			byteLen++
		}
		rawRand := make([]byte, byteLen)
		for randNum.BitLen() == 0 || randNum.BitLen() > bitLen {
			_, err = seededRand.Read(rawRand)
			if err != nil {
				return
			}
			randNum.SetBytes(rawRand)
			// set MSBs to 0 to get a bitLen equal to bitLen param.
			for bit := bitLen; bit < randNum.BitLen(); bit++ {
				randNum.SetBit(randNum, bit, 0)
			}
		}

		if randNum.BitLen() == 0 || randNum.BitLen() > bitLen {
			err = fmt.Errorf("random number returned should have length at most %d, but its length is %d", bitLen, randNum.BitLen())
			return
		}
		return
	}
}

// randomPrime returns a random prime of length bitLen, using a given random function randFn.
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

	for randPrime.BitLen() == 0 || randPrime.BitLen() > bitLen {
		randPrime, err = randFn(bitLen)
		if err != nil {
			return
		}
		setAsNextPrime(randPrime, c)
	}

	if randPrime.BitLen() == 0 || randPrime.BitLen() > bitLen {
		err = fmt.Errorf("random number returned should have length at most %d, but its length is %d", bitLen, randPrime.BitLen())
		return
	}

	if !randPrime.ProbablyPrime(c) {
		err = fmt.Errorf("random number returned is not prime")
		return
	}
	return
}

// setAsNextPrime edits the number as the next prime number from it, checking for its prime condition
// using ProbablyPrime function.
func setAsNextPrime(num *big.Int, n int) {
	// Possible prime should be odd
	num.SetBit(num, 0, 1)
	two := big.NewInt(2)
	for !num.ProbablyPrime(n) {
		// I add two to the number to obtain another odd number
		num.Add(num, two)
	}
}

// generateSafePrimes generates two primes p and q, in a way that q
// is equal to (p-1)/2. The greatest prime bit length is at least bitLen bits.
func generateSafePrimes(bitLen int, randFn func(int) (*big.Int, error)) (*big.Int, *big.Int, error) {
	if randFn == nil {
		return big.NewInt(0), big.NewInt(0), fmt.Errorf("random function cannot be nil")
	}

	q := new(big.Int)
	r := new(big.Int)

	for {
		p, err := randomPrime(bitLen, randFn)
		if err != nil {
			return big.NewInt(0), big.NewInt(0), err
		}

		// If the number will be odd after right shift
		if p.Bit(1) == 1 {
			// q = (p - 1) / 2
			q.Rsh(p, 1)
			if q.ProbablyPrime(c) {
				return p, q, nil
			}
		}

		if p.BitLen() < bitLen {
			// r = 2p + 1
			r.Lsh(p, 1)
			r.SetBit(r,0,1)
			if r.ProbablyPrime(c) {
				return r, p, nil
			}
		}
	}
}
