package tcrsa_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"github.com/niclabs/tcrsa"
)

const exampleK = 3
const exampleL = 5

const exampleHashType = crypto.SHA256
const exampleSize = 2048
const exampleMessage = "Hello world"

func Example() {
	// First we need to get the values of K and L from somewhere.
	k := uint16(exampleK)
	l := uint16(exampleL)

	// Generate keys provides to us with a list of keyShares and the key metainformation.
	keyShares, keyMeta, err := tcrsa.NewKey(exampleSize, uint16(k), uint16(l), nil)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	// Then we need to prepare the document we want to sign, so we hash it and pad it using PKCS v1.15.
	docHash := sha256.Sum256([]byte(exampleMessage))
	docPKCS1, err := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, docHash[:])
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	sigShares := make(tcrsa.SigShareList, l)
	var i uint16

	// Now we sign with at least k nodes and check immediately the signature share for consistency.
	for i = 0; i < l; i++ {
		sigShares[i], err = keyShares[i].Sign(docPKCS1, exampleHashType, keyMeta)
		if err != nil {
			panic(fmt.Sprintf("%v", err))
		}
		if err := sigShares[i].Verify(docPKCS1, keyMeta); err != nil {
			panic(fmt.Sprintf("%v", err))
		}
	}

	// Having all the signature shares we needed, we join them to create a real signature.
	signature, err := sigShares.Join(docPKCS1, keyMeta)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	// Finally we check the signature with Golang's crypto/rsa PKCSv1.15 verification routine.
	if err := rsa.VerifyPKCS1v15(keyMeta.PublicKey, crypto.SHA256, docHash[:], signature); err != nil {
		panic(fmt.Sprintf("%v", err))
	}
	fmt.Println("ok")
	// Output: ok
}
