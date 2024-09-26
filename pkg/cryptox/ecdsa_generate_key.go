/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	mrand "math/rand"

	"github.com/hyperledger/fabric/pkg/bbig/bridge"
	"github.com/hyperledger/fabric/pkg/bcy256"
)

func GenStdECDSAPrivateKey(_ elliptic.Curve) (*ecdsa.PrivateKey, error) {
	if useStd {
		return ecdsa.GenerateKey(Curve, rand.Reader)
	}

	x, y, d, err := bridge.GenerateKeyECDSA(Curve.Params().Name)
	if err != nil {
		return nil, fmt.Errorf("generate key ecdsa error: %w", err)
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: Curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}, nil
}

func GenCustomECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	pKey, err := ecdsa.GenerateKey(bcy256.Curve, mrand.New(mrand.NewSource(bcy256.Seed.Int64())))
	if err != nil {
		return nil, fmt.Errorf("custom private key error")
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: bcy256.Curve,
			X:     pKey.X,
			Y:     pKey.Y,
		},
		D: pKey.D,
	}, nil
}

func GenECDSAPrivateKey(_ elliptic.Curve) (ECDSAPrivateKey, error) {
	if useStd {
		priv, err := ecdsa.GenerateKey(Curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("gen std ecdsa key error: %w", err)
		}

		return &ecdsaPrivateKeyStd{
			private: priv,
		}, nil
	}

	x, y, d, err := bridge.GenerateKeyECDSA(Curve.Params().Name)
	if err != nil {
		return nil, fmt.Errorf("gen openssl ecdsa key error: %w", err)
	}

	return NewECDSAPrivateKey(Curve, x, y, d)
}
