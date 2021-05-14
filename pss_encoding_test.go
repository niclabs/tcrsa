package tcrsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPreparePssDocumentHash(t *testing.T) {
	var (
		pssEncodeTestMessage = "Hello World , Pss Encoding"
		pssEncodingLeyLength = 4096
	)

	docHash := sha256.Sum256([]byte(pssEncodeTestMessage))
	docPss, err := PreparePssDocumentHash(pssEncodingLeyLength, crypto.SHA256, docHash[:], &rsa.PSSOptions{
		SaltLength: 0,
		Hash:       crypto.SHA256,
	})
	assert.NoError(t, err)
	assert.Equal(t, pssEncodingLeyLength/8, len(docPss))
}
