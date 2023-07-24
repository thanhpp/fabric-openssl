/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opensslw

import (
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/microsoft/go-crypto-openssl/openssl"
	"github.com/microsoft/go-crypto-openssl/openssl/bbig/bridge"
)

type RSAPublicKey struct {
	k *openssl.PublicKeyRSA
	N *big.Int
	E int
}

func ConvertRSAPublicKey(key *rsa.PublicKey) (*RSAPublicKey, error) {
	mKey, err := bridge.NewPublicKeyRSA(key.N, big.NewInt(int64(key.E)))
	if err != nil {
		return nil, fmt.Errorf("new rsa pub key error: %+v", err)
	}

	return &RSAPublicKey{
		k: mKey,
		N: key.N,
		E: key.E,
	}, nil
}

func (k *RSAPublicKey) MarshalPKCS1PublicKey() []byte {
	derBytes, _ := asn1.Marshal(pkcs1PublicKey{
		N: k.N,
		E: k.E,
	})
	return derBytes
}

func GenerateCryptoRSAKey(bits int) (*rsa.PrivateKey, error) {
	N, E, D, P, Q, Dp, Dq, Qinv, err := bridge.GenerateKeyRSA(bits)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key error: %w", err)
	}

	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: N,
			E: int(E.Int64()),
		},
		D:      D,
		Primes: []*big.Int{P, Q},
		Precomputed: rsa.PrecomputedValues{
			Dp:        Dp,
			Dq:        Dq,
			Qinv:      Qinv,
			CRTValues: make([]rsa.CRTValue, 0), // non-nil, to match Precompute,
		},
	}, nil
}
