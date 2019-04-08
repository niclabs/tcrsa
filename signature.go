package main

type HashType int

const (
	NONE
	SHA256 = iota
)

type Signature []byte

