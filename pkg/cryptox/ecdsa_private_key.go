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
	"math/big"

	"github.com/hyperledger/fabric/pkg/bbig/bridge"
	"github.com/hyperledger/fabric/pkg/mopenssl"
)

type ECDSAPrivateKey interface {
	X() *big.Int
	Y() *big.Int
	D() *big.Int
	Curve() elliptic.Curve
	Public() ECDSAPublicKey
	Sign(digest []byte) ([]byte, error)
	SignRS(digest []byte) (r, s *big.Int, err error)
	VerifyPublicKey(hash []byte, r, s *big.Int) bool
}

func NewECDSAPrivateKey(curve elliptic.Curve, x, y, d *big.Int) (ECDSAPrivateKey, error) {
	if useStd {
		priv := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			},
			D: d,
		}

		return &ecdsaPrivateKeyStd{
			private: priv,
		}, nil
	}

	priv, err := bridge.NewPrivateKeyECDSA(curve.Params().Name, x, y, d)
	if err != nil {
		return nil, fmt.Errorf("new ecdsa private key error: %w", err)
	}

	pub, err := NewECDSAPublicKey(curve, x, y)
	if err != nil {
		return nil, fmt.Errorf("new ecdsa public key error: %w", err)
	}

	return &ecdsaPrivateKeyOpenSSL{
		public:  pub,
		private: priv,
		d:       d,
	}, nil
}

func ConvertECDSAPrivateKey(key *ecdsa.PrivateKey) (ECDSAPrivateKey, error) {
	return NewECDSAPrivateKey(key.Curve, key.X, key.Y, key.D)
}

// ------------------------------------------------------------------------------------------------
// ----------------------------------- ecdsaPrivateKeyOpenSSL -------------------------------------

type ecdsaPrivateKeyOpenSSL struct {
	public  ECDSAPublicKey
	private *mopenssl.PrivateKeyECDSA
	d       *big.Int
}

func (priv *ecdsaPrivateKeyOpenSSL) X() *big.Int {
	return priv.public.X()
}

func (priv *ecdsaPrivateKeyOpenSSL) Y() *big.Int {
	return priv.public.Y()
}

func (priv *ecdsaPrivateKeyOpenSSL) D() *big.Int {
	return priv.d
}

func (priv *ecdsaPrivateKeyOpenSSL) Curve() elliptic.Curve {
	return priv.public.Curve()
}

func (priv *ecdsaPrivateKeyOpenSSL) Public() ECDSAPublicKey {
	return priv.public
}

func (priv *ecdsaPrivateKeyOpenSSL) Sign(digest []byte) ([]byte, error) {
	r, s, err := priv.SignRS(digest)
	if err != nil {
		return nil, fmt.Errorf("sign ecdsa error: %w", err)
	}

	s, err = ECDSAToLowS(priv.public, s)
	if err != nil {
		return nil, fmt.Errorf("low s error: %w", err)
	}

	return marshalECDSASignature(r, s)
}

func (priv *ecdsaPrivateKeyOpenSSL) SignRS(digest []byte) (r, s *big.Int, err error) {
	return bridge.SignECDSA(priv.private, digest)
}

func (priv *ecdsaPrivateKeyOpenSSL) VerifyPublicKey(hash []byte, r, s *big.Int) bool {
	return priv.public.Verify(hash, r, s)
}

// ------------------------------------------------------------------------------------------------
// ------------------------------------- ecdsaPrivateKeyStd ---------------------------------------

type ecdsaPrivateKeyStd struct {
	private *ecdsa.PrivateKey
}

func (priv *ecdsaPrivateKeyStd) X() *big.Int {
	return priv.private.X
}

func (priv *ecdsaPrivateKeyStd) Y() *big.Int {
	return priv.private.Y
}

func (priv *ecdsaPrivateKeyStd) D() *big.Int {
	return priv.private.D
}

func (priv *ecdsaPrivateKeyStd) Curve() elliptic.Curve {
	return priv.private.Curve
}

func (priv *ecdsaPrivateKeyStd) Public() ECDSAPublicKey {
	return &ecdsaPublicKeyStd{
		pub: &priv.private.PublicKey,
	}
}

func (priv *ecdsaPrivateKeyStd) Sign(digest []byte) ([]byte, error) {
	r, s, err := priv.SignRS(digest)
	if err != nil {
		return nil, fmt.Errorf("sign ecdsa error: %w", err)
	}

	// ECDSAIsLowS
	halfOrder, ok := curveHalfOrders[priv.private.Params().Name]
	if !ok {
		return nil, fmt.Errorf("curve not recognized [%s]", priv.private.Params().Name)
	}

	lowS := s.Cmp(halfOrder) != 1

	// ECDSAToLowS
	if !lowS {
		// Set s to N - s that will be then in the lower part of signature space
		// less or equal to half order
		s.Sub(priv.private.Curve.Params().N, s)
	}

	return marshalECDSASignature(r, s)
}

func (priv *ecdsaPrivateKeyStd) SignRS(digest []byte) (r, s *big.Int, err error) {
	return ecdsa.Sign(rand.Reader, priv.private, digest)
}

func (priv *ecdsaPrivateKeyStd) VerifyPublicKey(hash []byte, r, s *big.Int) bool {
	return ecdsa.Verify(&priv.private.PublicKey, hash, r, s)
}
