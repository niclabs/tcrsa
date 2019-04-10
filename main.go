package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"math/big"
)

var kLong uint64
var lLong uint64
var s int
var m string
var fixedKey bool

const P = "+KYJ3Fn4XADnuZBgSUduw0RDgdlnTH4eb905ejItregpQp+/V28l3EXgD3A2Lz6Mm+Cg+JnoGIB0dEywh/6GGw=="
const Q = "TOUMXjftMP9kvE5ozJhSJQ0Lapn5QdqSCmPH38VseOq6QwK5dbQGdgcWFhg9J89NMBSry75n/okTQt+owG6xXw=="

func init() {
	flag.Uint64Var(&kLong, "k", 3, "Threshold size")
	flag.Uint64Var(&lLong, "l", 5, "Number of shares")
	flag.IntVar(&s, "s", 512, "key size in bits")
	flag.StringVar(&m, "m", "Hello world", "message")
	flag.BoolVar(&fixedKey, "f", false, "fixed example key")
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
	log.Printf("Generating %d keys for %d-threshold signing", l, k)

	keyMetaArgs := &KeyMetaArgs{}

	if fixedKey {
		log.Printf("Using fixed key args")
		pBig, err := base64.StdEncoding.DecodeString(P)
		if err != nil {
			panic("could not decode b64 key for p")
		}
		qBig, err := base64.StdEncoding.DecodeString(Q)
		if err != nil {
			panic("could not decode b64 key for q")
		}
		keyMetaArgs.P = new(big.Int).SetBytes(pBig)
		keyMetaArgs.Q = new(big.Int).SetBytes(qBig)
	}

	keyShares, keyMeta, err := GenerateKeys(s, uint16(k), uint16(l), keyMetaArgs)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}
	log.Printf("Preparing document hash for string \"%s\"", m)
	docHash := sha256.Sum256([]byte(m))

	hashB64 := base64.StdEncoding.EncodeToString(docHash[:])
	log.Printf("The document hash is %s", hashB64)

	docPKCS1, err := PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, docHash[:])
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	docB64 := base64.StdEncoding.EncodeToString(docPKCS1)

	log.Printf("The document pkcs1 prepared string is %s", docB64)

	sigShares := make(SignatureShares, l)

	var i uint16
	for i = 0; i < l; i++ {
		log.Printf("signing with node %d of %d", keyShares[i].Id, l)
		sigShares[i], err = keyShares[i].SignNode(docPKCS1, keyMeta)
		if err != nil {
			panic(fmt.Sprintf("%v", err))
		}
		log.Printf("verifying with node %d of %d", sigShares[i].Id, l)
		if !sigShares[i].Verify(docPKCS1, keyMeta) {
			panic("signature doesn't match")
		}
	}
	log.Printf("joining sigShares")
	signature, err := sigShares.Join(docPKCS1, keyMeta)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	sigB64 := base64.StdEncoding.EncodeToString(signature)
	log.Printf("The document signature (bitlen %d) is %s", len(signature), sigB64)

	log.Printf("verifying signature")
	if err := rsa.VerifyPKCS1v15(keyMeta.PublicKey, crypto.SHA256, docHash[:], signature); err != nil {
		panic(fmt.Sprintf("%v", err))
	}
	log.Printf("done!")
}
