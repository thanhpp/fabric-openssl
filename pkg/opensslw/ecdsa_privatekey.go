/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opensslw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/microsoft/go-crypto-openssl/openssl"
	"github.com/microsoft/go-crypto-openssl/openssl/bbig/bridge"
)

type ECDSAPrivateKey struct {
	Public  *ECDSAPublicKey
	private *openssl.PrivateKeyECDSA
	D       *big.Int
}

func NewECDSAPrivateKey(curve elliptic.Curve, x, y, d *big.Int) (*ECDSAPrivateKey, error) {
	priv, err := bridge.NewPrivateKeyECDSA(curve.Params().Name, x, y, d)
	if err != nil {
		return nil, fmt.Errorf("new ecdsa private key error: %w", err)
	}

	pub, err := NewECDSAPublicKey(curve, x, y)
	if err != nil {
		return nil, fmt.Errorf("new ecdsa public key error: %w", err)
	}

	return &ECDSAPrivateKey{
		Public:  pub,
		private: priv,
		D:       d,
	}, nil
}

func ConvertECDSAPrivateKey(key *ecdsa.PrivateKey) (*ECDSAPrivateKey, error) {
	priv, err := bridge.NewPrivateKeyECDSA(key.Params().Name, key.X, key.Y, key.D)
	if err != nil {
		return nil, fmt.Errorf("new ecdsa private key error: %w", err)
	}

	pub, err := ConvertECDSAPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	return &ECDSAPrivateKey{
		Public:  pub,
		private: priv,
		D:       key.D,
	}, nil
}

func (k *ECDSAPrivateKey) Sign(digest []byte) ([]byte, error) {
	r, s, err := bridge.SignECDSA(k.private, digest)
	if err != nil {
		return nil, fmt.Errorf("sign ecdsa error: %w", err)
	}

	s, err = ECDSAToLowS(k.Public, s)
	if err != nil {
		return nil, fmt.Errorf("low s error: %w", err)
	}

	return marshalECDSASignature(r, s)
}

func (k *ECDSAPrivateKey) SignRS(digest []byte) (r, s *big.Int, err error) {
	return bridge.SignECDSA(k.private, digest)
}

func (k *ECDSAPrivateKey) VerifyPublicKey(hash []byte, r, s *big.Int) bool {
	return bridge.VerifyECDSA(k.Public.pub, hash, r, s)
}

// copy from bccsp/utils/ecdsa.go
func marshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ECDSASignature{r, s})
}

type ECDSASignature struct {
	R, S *big.Int
}
