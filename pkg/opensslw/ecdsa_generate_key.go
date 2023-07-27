/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opensslw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	"github.com/microsoft/go-crypto-openssl/openssl"
	"github.com/microsoft/go-crypto-openssl/openssl/bbig"
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

func ECDSAGenerateOpenSSLKey(c elliptic.Curve) (*ECDSAPrivateKey, error) {
	name := c.Params().Name

	x, y, d, err := openssl.GenerateKeyECDSA(name)
	if err != nil {
		return nil, fmt.Errorf("generate key ecdsa error: %w", err)
	}

	priv, err := openssl.NewPrivateKeyECDSA(name, x, y, d)
	if err != nil {
		return nil, fmt.Errorf("new ecdsa private key error: %w", err)
	}

	pub, err := openssl.NewPublicKeyECDSA(name, x, y)
	if err != nil {
		return nil, fmt.Errorf("new ecdsa public key error: %w", err)
	}

	return &ECDSAPrivateKey{
		Public: &ECDSAPublicKey{
			pub:   pub,
			Curve: c,
			X:     bbig.Dec(x),
			Y:     bbig.Dec(y),
		},
		private: priv,
		D:       bbig.Dec(d),
	}, nil
}
