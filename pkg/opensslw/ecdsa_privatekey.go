/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opensslw

import (
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/microsoft/go-crypto-openssl/openssl"
	"github.com/microsoft/go-crypto-openssl/openssl/bbig/bridge"
)

type ECDSAPrivateKey struct {
	Public  *ECDSAPublicKey
	private *openssl.PrivateKeyECDSA
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
