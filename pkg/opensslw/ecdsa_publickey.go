/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opensslw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/microsoft/go-crypto-openssl/openssl"
	"github.com/microsoft/go-crypto-openssl/openssl/bbig"
	"github.com/microsoft/go-crypto-openssl/openssl/bbig/bridge"
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

type ECDSAPublicKey struct {
	pub *openssl.PublicKeyECDSA
	// Curve info
	Curve elliptic.Curve
	X, Y  *big.Int
}

func NewECDSAPublicKey(curve elliptic.Curve, x, y *big.Int) (*ECDSAPublicKey, error) {
	pub, err := bridge.NewPublicKeyECDSA(curve.Params().Name, x, y)
	if err != nil {
		return nil, fmt.Errorf("new public key ecdsa error: %w", err)
	}

	return &ECDSAPublicKey{
		pub:   pub,
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func (pub *ECDSAPublicKey) CurveBitSize() int {
	return pub.Curve.Params().BitSize
}

func (pub *ECDSAPublicKey) Verify(hash []byte, r, s *big.Int) bool {
	return bridge.VerifyECDSA(pub.pub, hash, r, s)
}

func (pub *ECDSAPublicKey) GetCurveHaftOrder() *big.Int {
	return new(big.Int).Set(curveHalfOrders[pub.Curve.Params().Name])
}

func (pub *ECDSAPublicKey) MarshalPKIXPublicKey() ([]byte, error) {
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier

	oid, ok := oidNamedCurves[pub.Curve.Params().Name]
	if !ok {
		return nil, fmt.Errorf("unsupported elliptic curve: [%s]", pub.Curve.Params().Name)
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("invalid elliptic curve public key")
	}
	publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
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

func ConvertECDSAPublicKey(cPubKey *ecdsa.PublicKey) (*ECDSAPublicKey, error) {
	pubK, err := openssl.NewPublicKeyECDSA(cPubKey.Params().Name, bbig.Enc(cPubKey.X), bbig.Enc(cPubKey.Y))
	if err != nil {
		return nil, fmt.Errorf("new ecdsa public key error: %w", err)
	}

	return &ECDSAPublicKey{
		pub:   pubK,
		Curve: cPubKey.Curve,
		X:     cPubKey.X,
		Y:     cPubKey.Y,
	}, nil
}

func ECDSAIsLowS(pubKey *ECDSAPublicKey, s *big.Int) (bool, error) {
	halfOrder, ok := curveHalfOrders[pubKey.Curve.Params().Name]
	if !ok {
		return false, fmt.Errorf("curve not recognized [%s]", pubKey.Curve.Params().Name)
	}

	return s.Cmp(halfOrder) != 1, nil
}

func ECDSAToLowS(k *ECDSAPublicKey, s *big.Int) (*big.Int, error) {
	lowS, err := ECDSAIsLowS(k, s)
	if err != nil {
		return nil, err
	}

	if !lowS {
		// Set s to N - s that will be then in the lower part of signature space
		// less or equal to half order
		s.Sub(k.Curve.Params().N, s)

		return s, nil
	}

	return s, nil
}
