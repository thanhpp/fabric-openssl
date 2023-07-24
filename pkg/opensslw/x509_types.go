/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opensslw

import "math/big"

// pkcs1PublicKey reflects the ASN.1 structure of a PKCS #1 public key. (ported from x509)
type pkcs1PublicKey struct {
	N *big.Int
	E int
}
