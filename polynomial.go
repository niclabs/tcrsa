package main

import (
	"fmt"
	"math/big"
	"strings"
)

type Polynomial []*big.Int

// Creates a polynomial of degree d with all its d+1 coefficients in 0.
func NewPolynomial(d int) Polynomial {
	poly := make(Polynomial, d + 1)
	for i := 0; i < len(poly); i++ {
		poly[i] = new(big.Int)
	}
	return poly
}

// Returns the degree of a polynomial, which is the length of the coefficient
// array, minus 1.
func (p Polynomial) getDegree() int {
	return len(p) - 1
}

// Creates a polynomial of degree "d" with random coefficients for terms with degree
// greater than 1. The coefficient of the term of degree 0 is x0 and the module of the
// coefficients for the polynomial is m.
func CreateRandomPolynomial(d int, x0, m *big.Int) (Polynomial, error) {
	if m.Sign() < 0 {
		return Polynomial{}, fmt.Errorf("m is negative")
	}
	bitLen := m.BitLen() - 1
	poly := NewPolynomial(d)

	poly[0].Set(x0)

	for i := 1; i < len(poly); i++ {
		rand, err := randomDev(bitLen)
		if err != nil {
			return Polynomial{}, err
		}
		poly[i].Mod(rand, m)
	}
	return poly, nil
}

// Creates a polynomial of degree "d" with fixed coefficients for terms with degree
// greater than 1. The coefficient of the term of degree 0 is x0 and the module of the
// coefficients for the polynomial is m.
func CreateFixedPolynomial(d int, x0, m *big.Int) (Polynomial, error) {
	if m.Sign() < 0 {
		return Polynomial{}, fmt.Errorf("m is negative")
	}
	poly := NewPolynomial(d)
	poly[0].Set(x0)

	for i := 1; i < len(poly); i++ {
		rand := big.NewInt(int64(i))
		poly[i].Mod(rand, m)
	}
	return poly, nil
}

// Evaluates a polynomial with Horner's method.
func (p Polynomial) Eval(x *big.Int) *big.Int {
	y := big.NewInt(0)
	for k := len(p) - 1; k >= 0; k-- {
		y.Mul(y, x)
		y.Add(y,p[k])
	}
	return y
}

func (p Polynomial) String() string {
	s := make([]string, len(p))
	for i := 0; i < len(p); i++ {
		s[i] = fmt.Sprintf("%dx^%d", p[i], i)
	}
	return strings.Join(s, " + ")
}