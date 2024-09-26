/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptox

import (
	"crypto/x509"
	"math/big"

	cx509 "github.com/hyperledger/fabric/pkg/cryptox/x509"
)

// pkcs1PublicKey reflects the ASN.1 structure of a PKCS #1 public key. (ported from x509)
type pkcs1PublicKey struct {
	N *big.Int
	E int
}

func ParseCertPool(in *cx509.CertPool) *x509.CertPool {
	return &x509.CertPool{}
}
