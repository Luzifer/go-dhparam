package dhparam

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
)

// DH contains a prime (P) and a generator (G) number representing the DH parameters
type DH struct {
	P *big.Int
	G int
}

// Decode reads a DH parameters struct from its PEM data
func Decode(pemData []byte) (*DH, error) {
	blk, _ := pem.Decode(pemData)

	out := &DH{}
	if _, err := asn1.Unmarshal(blk.Bytes, out); err != nil {
		return nil, fmt.Errorf("could not unmarshal ASN1: %w", err)
	}

	return out, nil
}

// ToPEM encodes the DH parameters using ASN1 and PEM encoding
func (d DH) ToPEM() ([]byte, error) {
	data, err := asn1.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal ASN1 data: %w", err)
	}

	buf := new(bytes.Buffer)
	err = pem.Encode(buf, &pem.Block{
		Type:  pemHeader,
		Bytes: data,
	})

	return buf.Bytes(), err
}
