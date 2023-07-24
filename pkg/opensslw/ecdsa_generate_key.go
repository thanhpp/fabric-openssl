/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opensslw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	"github.com/microsoft/go-crypto-openssl/openssl/bbig/bridge"
)

func ECDSAGenerateKey(c elliptic.Curve) (*ecdsa.PrivateKey, error) {
	x, y, d, err := bridge.GenerateKeyECDSA(c.Params().Name)
	if err != nil {
		return nil, fmt.Errorf("generate key ecdsa error: %w", err)
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: c,
			X:     x,
			Y:     y,
		},
		D: d,
	}, nil
}
