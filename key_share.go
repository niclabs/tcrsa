package main

import "fmt"

type KeyShare struct {
	Si []byte
	N  []byte
	Id uint16
}

type KeyShares []*KeyShare


func NewKeyShares(keyMeta *KeyMeta) (KeyShares, error) {
	if keyMeta.L <= 0 {
		return KeyShares{}, fmt.Errorf("l in KeyMeta should be greater than 0, but it is %d", keyMeta.L)
	}
	keyShares := make(KeyShares, keyMeta.L)
	var i uint16
	for i = 0; i < keyMeta.L; i++ {
		keyShares[i] = &KeyShare{}
	}
	return keyShares, nil
}