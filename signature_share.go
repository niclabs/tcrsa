package main

import "fmt"

type SignatureShare struct {
	Xi []byte
	c []byte
	z []byte
	id uint16
}


type SignatureShares []SignatureShare


// Joins the signatures of the document provided.
func (s SignatureShares) JoinSignatures(document []byte, info *KeyMeta) ([]byte, error) {
	if document == nil {
		return []byte{}, fmt.Errorf("document is nil")
	}
	if info == nil {
		return []byte{}, fmt.Errorf("key metainfo is nil")
	}

}