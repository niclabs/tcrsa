package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
)

const keyTestBitLen = 512
const keyTestK = 3
const keyTestL = 5

const keyTestFixedP = "132TWiSEqNNnfiF5AZjS2R8SwUszMGnHSKTYAtWckuc="
const keyTestFixedQ = "f8PooDmAlOUFf3BdAxPCOy8p5ArfLHs6ODFWTFnpUxM="
const keyTestFixedR = "UfF0MWqXf+K4GjmcWhxdK3CH/XVsDxm8r+CqBenL7TfdWNAD4rpUMIHzhqb0WV6KAAJfGEBlHyj1JH2rr9LiUA=="
const keyTestFixedU = "CpJe+VzsAI3FcPioeMXklkxFFb+M9MaN1VzuScOs+7bwvczarYABZhyjPFC8McXCFAJIvaKTZwTlpylwJPumZw=="

func TestGenerateKeys_differentKeys(t *testing.T) {
	keyShares, _, err := GenerateKeys(keyTestBitLen, keyTestK, keyTestL, &KeyMetaArgs{})
	if err != nil {
		t.Errorf("couldn't create keys")
	}

	for i := 0; i < len(keyShares); i++ {
		key1 := keyShares[i]
		for j := i + 1; j < len(keyShares); j++ {
			key2 := keyShares[j]
			if key1.EqualsSi(key2) {
				t.Errorf("key shares are equal: k%d=%s, k%d=%s", i, key1.toBase64(), j, key2.toBase64())
			}
		}
	}
}

func TestGenerateKeys_validRandom(t *testing.T) {
	// check that k and l are less than 2^16-1
	if kLong >= 1<<16-1 || kLong <= 0 {
		t.Errorf("k should be between 1 and 65535")
	}

	if lLong >= 1<<16-1 || lLong <= 0 {
		t.Errorf("l should be between 1 and 65535")
	}

	k := uint16(kLong)
	l := uint16(lLong)

	keyMetaArgs := &KeyMetaArgs{}

	keyShares, keyMeta, err := GenerateKeys(s, uint16(k), uint16(l), keyMetaArgs)
	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}
	docHash := sha256.Sum256([]byte(m))

	docPKCS1, err := PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, docHash[:])
	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}

	sigShares := make(SigShareList, l)

	var i uint16
	for i = 0; i < l; i++ {
		sigShares[i], err = keyShares[i].NodeSign(docPKCS1, keyMeta)
		if err != nil {
			t.Errorf(fmt.Sprintf("%v", err))
		}
		if err := sigShares[i].Verify(docPKCS1, keyMeta); err != nil {
			panic(fmt.Sprintf("%v", err))
		}
	}
	signature, err := sigShares.Join(docPKCS1, keyMeta)
	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}

	if err := rsa.VerifyPKCS1v15(keyMeta.PublicKey, crypto.SHA256, docHash[:], signature); err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}

}

func TestGenerateKeys_validFixed(t *testing.T) {

	if kLong >= 1<<16-1 || kLong <= 0 {
		t.Errorf("k should be between 1 and 65535")
	}

	if lLong >= 1<<16-1 || lLong <= 0 {
		t.Errorf("l should be between 1 and 65535")
	}

	k := uint16(kLong)
	l := uint16(lLong)

	keyMetaArgs := &KeyMetaArgs{}

	pBig, err := base64.StdEncoding.DecodeString(keyTestFixedP)
	if err != nil {
		t.Errorf("could not decode b64 key for p")
	}
	qBig, err := base64.StdEncoding.DecodeString(keyTestFixedQ)
	if err != nil {
		t.Errorf("could not decode b64 key for q")
	}
	rBig, err := base64.StdEncoding.DecodeString(keyTestFixedR)
	if err != nil {
		t.Errorf("could not decode b64 key for R")
	}
	vkuBig, err := base64.StdEncoding.DecodeString(keyTestFixedU)
	if err != nil {
		t.Errorf("could not decode b64 key for vk_u")
	}
	keyMetaArgs.P = new(big.Int).SetBytes(pBig)
	keyMetaArgs.Q = new(big.Int).SetBytes(qBig)
	keyMetaArgs.R = new(big.Int).SetBytes(rBig)
	keyMetaArgs.U = new(big.Int).SetBytes(vkuBig)
	keyMetaArgs.FixedPoly = true

	keyShares, keyMeta, err := GenerateKeys(s, uint16(k), uint16(l), keyMetaArgs)
	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}
	docHash := sha256.Sum256([]byte(m))

	docPKCS1, err := PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, docHash[:])
	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}

	sigShares := make(SigShareList, l)

	var i uint16
	for i = 0; i < l; i++ {
		sigShares[i], err = keyShares[i].NodeSign(docPKCS1, keyMeta)
		if err != nil {
			t.Errorf(fmt.Sprintf("%v", err))
		}
		if err := sigShares[i].Verify(docPKCS1, keyMeta); err != nil {
			panic(fmt.Sprintf("%v", err))
		}
	}
	signature, err := sigShares.Join(docPKCS1, keyMeta)

	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}

	sigB64 := base64.StdEncoding.EncodeToString(signature)

	if sigB64 != "BUNv4j1NkVFNwx6v0GVG6CfN1Y7yhOBG2Tyy7ci7VK+AVYukZdiajnaYPALHLsEwngDLgNPK40o6HhbWT+ikXQ==" {
		t.Errorf("signature is not as expected.")
	}

	if err := rsa.VerifyPKCS1v15(keyMeta.PublicKey, crypto.SHA256, docHash[:], signature); err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}

}
