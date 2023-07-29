/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptox

import (
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// curveHalfOrders contains the precomputed curve group orders halved.
// It is used to ensure that signature' S value is lower or equal to the
// curve group order halved. We accept only low-S signatures.
// They are precomputed for efficiency reasons.
var curveHalfOrders = map[string]*big.Int{
	"P-224": new(big.Int).Rsh(elliptic.P224().Params().N, 1),
	"P-256": new(big.Int).Rsh(elliptic.P256().Params().N, 1),
	"P-384": new(big.Int).Rsh(elliptic.P384().Params().N, 1),
	"P-521": new(big.Int).Rsh(elliptic.P521().Params().N, 1),
}

var oidNamedCurves = map[string]asn1.ObjectIdentifier{
	"P-224": {1, 3, 132, 0, 33},
	"P-256": {1, 2, 840, 10045, 3, 1, 7},
	"P-384": {1, 3, 132, 0, 34},
	"P-521": {1, 3, 132, 0, 35},
}

var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

func ECDSAIsLowS(pubKey ECDSAPublicKey, s *big.Int) (bool, error) {
	halfOrder, ok := curveHalfOrders[pubKey.Curve().Params().Name]
	if !ok {
		return false, fmt.Errorf("curve not recognized [%s]", pubKey.Curve().Params().Name)
	}

	return s.Cmp(halfOrder) != 1, nil
}

func ECDSAToLowS(k ECDSAPublicKey, s *big.Int) (*big.Int, error) {
	lowS, err := ECDSAIsLowS(k, s)
	if err != nil {
		return nil, err
	}

	if !lowS {
		// Set s to N - s that will be then in the lower part of signature space
		// less or equal to half order
		s.Sub(k.Curve().Params().N, s)

		return s, nil
	}

	return s, nil
}

// copy from bccsp/utils/ecdsa.go
type ECDSASignature struct {
	R, S *big.Int
}

func marshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ECDSASignature{r, s})
}
