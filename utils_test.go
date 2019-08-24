package tcrsa

import (
	"math/big"
	"testing"
)

const utilsTestBitlen = 256

// Miller-Rabin primality test rounds
const utilsTestC = 25

// Tests that two consecutive outputs from random dev are different.
// TODO: Test how much different are the numbers generated
func TestRandomDev_different(t *testing.T) {
	rand1, err := randomDev(utilsTestBitlen)
	if err != nil {
		t.Errorf("first random number generation failed: %v", err)
	}
	rand2, err := randomDev(utilsTestBitlen)
	if err != nil {
		t.Errorf("second random number generation failed: %v", err)
	}
	if rand1.Cmp(rand2) == 0 {
		t.Errorf("both random numbers are equal!")
	}
}

// Tests that the bit size of the output of a random dev function is the desired.
func TestRandomDev_bitSize(t *testing.T) {
	rand1, err := randomDev(utilsTestBitlen)
	if err != nil {
		t.Errorf("first random number generation failed: %v", err)
	}
	if rand1.BitLen() > utilsTestBitlen {
		t.Errorf("random number bit length should have been at most %d, but it was %d", rand1.BitLen(), utilsTestBitlen)
	}
}

// Tests that two consecutive random primes are different.
// TODO: Test how much different are the numbers generated
func TestRandomPrimes_different(t *testing.T) {
	rand1, err := randomPrime(utilsTestBitlen, randomDev)
	if err != nil {
		t.Errorf("first random prime number generation failed: %v", err)
	}
	rand2, err := randomPrime(utilsTestBitlen, randomDev)
	if err != nil {
		t.Errorf("second random prime number generation failed: %v", err)
	}
	if rand1.Cmp(rand2) == 0 {
		t.Errorf("both random numbers are equal!")
	}
}

// Tests that the output size of a random prime function is the desired.
func TestRandomPrimes_bitSize(t *testing.T) {
	rand1, err := randomPrime(utilsTestBitlen, randomDev)
	if err != nil {
		t.Errorf("first random prime number generation failed: %v", err)
	}
	if rand1.BitLen() > utilsTestBitlen {
		t.Errorf("random number bit length should have been at most %d, but it was %d", rand1.BitLen(), utilsTestBitlen)
	}
}

// Tests that the output of RandomPrimes is a prime.
func TestRandomPrimes_isPrime(t *testing.T) {
	rand1, err := randomPrime(utilsTestBitlen, randomDev)
	if err != nil {
		t.Errorf("first random prime number generation failed: %v", err)
	}
	if !rand1.ProbablyPrime(utilsTestC) {
		t.Errorf("random number is not prime")
	}
}

// Tests that NextPrime returns the next prime of a number greater than 2.
func TestNextPrime(t *testing.T) {
	number := big.NewInt(4)
	firstNumber := big.NewInt(0)
	firstNumber.Set(number)
	expected := big.NewInt(5)
	setAsNextPrime(number, utilsTestC)
	if number.Cmp(expected) != 0 {
		t.Errorf("expecting %s as next prime of %s, but obtained %s", expected, firstNumber, number)
	}
}

func TestGenerateSafePrimes(t *testing.T) {

	pExpected := new(big.Int)

	p, pr, err := generateSafePrimes(utilsTestBitlen, randomDev)
	if err != nil {
		t.Errorf("safe prime generation failed: %v", err)
	}
	if !p.ProbablyPrime(utilsTestC) {
		t.Errorf("p is not prime")
	}
	if !pr.ProbablyPrime(utilsTestC) {
		t.Errorf("pr is not prime")
	}
	pExpected.Mul(pr, big.NewInt(2)).Add(pExpected, big.NewInt(1))
	if p.Cmp(pExpected) != 0 {
		t.Errorf("p is not 2*pr + 1")
	}
}

func TestGenerateSafePrimes_keyGeneration(t *testing.T) {

	m := new(big.Int)
	d := new(big.Int)
	r := new(big.Int)

	_, pr, err := generateSafePrimes(utilsTestBitlen, randomDev)
	if err != nil {
		t.Errorf("safe prime generation failed: %v", err)
	}

	_, qr, err := generateSafePrimes(utilsTestBitlen, randomDev)
	if err != nil {
		t.Errorf("safe prime generation failed: %v", err)
	}

	m.Mul(pr, qr)
	e := big.NewInt(65537)

	d.ModInverse(e, m)
	r.Mul(d, e).Mod(r, m)

	if r.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("safe prime generation failed")
	}

}


func BenchmarkSetAsPrime(b *testing.B) {
	randFn := randomFixed(12345)
	for i := 0; i < b.N; i++ {
		randPrime := big.NewInt(0)
		for randPrime.BitLen() == 0 || randPrime.BitLen() > utilsTestBitlen {
			randPrime, _ = randFn(utilsTestBitlen)
			setAsNextPrime(randPrime, c)
		}
	}
}
