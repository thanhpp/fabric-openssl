/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/hyperledger/fabric/pkg/cryptox/x509"

	"github.com/hyperledger/fabric/pkg/bbig/bridge"
	"github.com/hyperledger/fabric/pkg/mopenssl"
)

type ECDSAPublicKey interface {
	Curve() elliptic.Curve
	X() *big.Int
	Y() *big.Int
	CurveBitSize() int
	Verify(hash []byte, r, s *big.Int) bool
	GetCurveHaftOrder() *big.Int
	MarshalPKIXPublicKey() ([]byte, error)
}

func NewECDSAPublicKey(curve elliptic.Curve, x, y *big.Int) (ECDSAPublicKey, error) {
	if useStd {
		return &ecdsaPublicKeyStd{
			pub: &ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			},
		}, nil
	}

	pub, err := bridge.NewPublicKeyECDSA(curve.Params().Name, x, y)
	if err != nil {
		return nil, fmt.Errorf("new public key ecdsa error: %w", err)
	}

	return &ecdsaPublicKeyOpenSSL{
		pub:   pub,
		curve: curve,
		x:     x,
		y:     y,
	}, nil
}

func ConvertECDSAPublicKey(key *ecdsa.PublicKey) (ECDSAPublicKey, error) {
	return NewECDSAPublicKey(key.Curve, key.X, key.Y)
}

// ------------------------------------------------------------------------------------------------
// ------------------------------------- ecdsaPublicKeyOpenSSL ------------------------------------

type ecdsaPublicKeyOpenSSL struct {
	pub *mopenssl.PublicKeyECDSA
	// Curve info
	curve elliptic.Curve
	x, y  *big.Int
}

func (pub *ecdsaPublicKeyOpenSSL) Curve() elliptic.Curve {
	return pub.curve
}

func (pub *ecdsaPublicKeyOpenSSL) X() *big.Int {
	return pub.x
}

func (pub *ecdsaPublicKeyOpenSSL) Y() *big.Int {
	return pub.y
}

func (pub *ecdsaPublicKeyOpenSSL) CurveBitSize() int {
	return pub.curve.Params().BitSize
}

func (pub *ecdsaPublicKeyOpenSSL) Verify(hash []byte, r, s *big.Int) bool {
	return bridge.VerifyECDSA(pub.pub, hash, r, s)
}

func (pub *ecdsaPublicKeyOpenSSL) GetCurveHaftOrder() *big.Int {
	return new(big.Int).Set(curveHalfOrders[pub.curve.Params().Name])
}

func (pub *ecdsaPublicKeyOpenSSL) MarshalPKIXPublicKey() ([]byte, error) {
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier

	oid, ok := oidNamedCurves[pub.curve.Params().Name]
	if !ok {
		return nil, fmt.Errorf("unsupported elliptic curve: [%s]", pub.curve.Params().Name)
	}
	if !pub.curve.IsOnCurve(pub.x, pub.y) {
		return nil, errors.New("invalid elliptic curve public key")
	}
	publicKeyBytes = elliptic.Marshal(pub.curve, pub.x, pub.y)
	publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
	paramBytes, err := asn1.Marshal(oid)
	if err != nil {
		return nil, fmt.Errorf("marshal oid error: %w", err)
	}
	publicKeyAlgorithm.Parameters.FullBytes = paramBytes

	type pkixPublicKey struct {
		Algo      pkix.AlgorithmIdentifier
		BitString asn1.BitString
	}

	pkix := pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	}

	return asn1.Marshal(pkix)
}

// ------------------------------------------------------------------------------------------------
// --------------------------------------- ecdsaPublicKeyStd --------------------------------------

type ecdsaPublicKeyStd struct {
	pub *ecdsa.PublicKey
}

func (pub *ecdsaPublicKeyStd) Curve() elliptic.Curve {
	return pub.pub.Curve
}

func (pub *ecdsaPublicKeyStd) X() *big.Int {
	return pub.pub.X
}

func (pub *ecdsaPublicKeyStd) Y() *big.Int {
	return pub.pub.Y
}

func (pub *ecdsaPublicKeyStd) CurveBitSize() int {
	return pub.pub.Params().BitSize
}

func (pub *ecdsaPublicKeyStd) Verify(hash []byte, r, s *big.Int) bool {
	return ecdsa.Verify(pub.pub, hash, r, s)
}

func (pub *ecdsaPublicKeyStd) GetCurveHaftOrder() *big.Int {
	return new(big.Int).Set(curveHalfOrders[pub.pub.Curve.Params().Name])
}

func (pub *ecdsaPublicKeyStd) MarshalPKIXPublicKey() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub.pub)
}
