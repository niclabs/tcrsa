package tcrsa

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

// Number of Miller-Rabin tests
const c = 20

// randInt is a function which generates a random big number, using crypto/rand
// crypto-secure Golang library.
func randInt(bitLen int) (randNum *big.Int, err error) {
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

// generateSafePrimes generates two primes p and q, in a way that q
// is equal to (p-1)/2. The greatest prime bit length is at least bitLen bits.
func generateSafePrimes(bitLen int, randSource io.Reader) (*big.Int, *big.Int, error) {
	if randSource == nil {
		return big.NewInt(0), big.NewInt(0), fmt.Errorf("random source cannot be nil")
	}
	p := new(big.Int)

	for {
		q, err := rand.Prime(randSource, bitLen-1)
		if err != nil {
			return big.NewInt(0), big.NewInt(0), err
		}
		// p = 2q + 1
		p.Lsh(q, 1)
		p.SetBit(p,0,1)
		if p.ProbablyPrime(c) {
			return p, q, nil
		}
	}
}

