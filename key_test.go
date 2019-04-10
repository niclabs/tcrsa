package main

import "testing"

const keyTestBitLen = 512
const keyTestK = 3
const keyTestL = 5

func TestGenerateKeys_differentKeys(t *testing.T) {
	keyShares, _, err := GenerateKeys(keyTestBitLen, keyTestK, keyTestL, &KeyMetaArgs{})
	if err != nil {
		t.Errorf("couldn't create keys")
	}

	for i := 0; i < len(keyShares); i++ {
		key1 := keyShares[i]
		for j:=i+1; j < len(keyShares); j++ {
			key2 := keyShares[j]
			if key1.Equals(key2) {
				t.Errorf("key shares are equal: k%d=%s, k%d=%s", i, key1.toBase64(), j, key2.toBase64())
			}
		}
	}
}
