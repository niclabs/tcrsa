package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
)

var kLong uint64
var lLong uint64
var s int
var m string

func init() {
	flag.Uint64Var(&kLong, "k", 3, "Threshold size")
	flag.Uint64Var(&lLong, "l", 5, "Number of shares")
	flag.IntVar(&s, "s", 512, "key size in bits")
	flag.StringVar(&m, "m", "Hello world", "message")
}

func main() {
	flag.Parse()

	// check that k and l are less than 2^16-1
	if kLong >= 1<<16-1 || kLong <= 0 {
		panic("k should be between 1 and 65535")
	}

	if lLong >= 1<<16-1 || lLong <= 0 {
		panic("l should be between 1 and 65535")
	}

	k := uint16(kLong)
	l := uint16(lLong)

	keyMetaArgs := &KeyMetaArgs{}

	keyShares, keyMeta, err := GenerateKeys(s, uint16(k), uint16(l), keyMetaArgs)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}
	docHash := sha256.Sum256([]byte(m))

	docPKCS1, err := PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, docHash[:])
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	docB64 := base64.StdEncoding.EncodeToString(docPKCS1)
	log.Printf("Document: %s", docB64)

	sigShares := make(SignatureShares, l)

	var i uint16
	for i = 0; i < l; i++ {
		sigShares[i], err = keyShares[i].SignNode(docPKCS1, keyMeta)
		if err != nil {
			panic(fmt.Sprintf("%v", err))
		}
		if !sigShares[i].Verify(docPKCS1, keyMeta) {
			panic("signature doesn't match")
		}
	}
	signature, err := sigShares.Join(docPKCS1, keyMeta)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	sigB64 := base64.StdEncoding.EncodeToString(signature)
	log.Printf("Signature: %s", sigB64)

	if err := rsa.VerifyPKCS1v15(keyMeta.PublicKey, crypto.SHA256, docHash[:], signature); err != nil {
		panic(fmt.Sprintf("%v", err))
	}
}
