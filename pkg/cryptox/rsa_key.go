/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptox

import (
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/hyperledger/fabric/pkg/ccs-gm/x509"

	"github.com/hyperledger/fabric/pkg/bbig/bridge"
	"github.com/hyperledger/fabric/pkg/mopenssl"
)

type RSAPublicKey interface {
	N() *big.Int
	E() int
	MarshalPKCS1PublicKey() []byte
}

func ConvertRSAPublicKey(key *rsa.PublicKey) (RSAPublicKey, error) {
	if useStd {
		return &rsaPublicKeyStd{
			k: key,
		}, nil
	}

	mKey, err := bridge.NewPublicKeyRSA(key.N, big.NewInt(int64(key.E)))
	if err != nil {
		return nil, fmt.Errorf("new rsa pub key error: %+v", err)
	}

	return &rsaPublicKeyOpenSSL{
		k: mKey,
		n: key.N,
		e: key.E,
	}, nil
}

func GenerateRSAKeyStd(bits int) (*rsa.PrivateKey, error) {
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

// ------------------------------------------------------------------------------------------------
// ------------------------------------ rsaPublicKeyOpenSSL --------------------------------------

type rsaPublicKeyOpenSSL struct {
	k *mopenssl.PublicKeyRSA
	n *big.Int
	e int
}

func (pub *rsaPublicKeyOpenSSL) N() *big.Int {
	return pub.n
}

func (pub *rsaPublicKeyOpenSSL) E() int {
	return pub.e
}

func (pub *rsaPublicKeyOpenSSL) MarshalPKCS1PublicKey() []byte {
	derBytes, _ := asn1.Marshal(pkcs1PublicKey{
		N: pub.n,
		E: pub.e,
	})
	return derBytes
}

// ------------------------------------------------------------------------------------------------
// -------------------------------------- rsaPublicKeyStd ----------------------------------------

type rsaPublicKeyStd struct {
	k *rsa.PublicKey
}

func (pub *rsaPublicKeyStd) N() *big.Int {
	return pub.k.N
}

func (pub *rsaPublicKeyStd) E() int {
	return pub.k.E
}

func (pub *rsaPublicKeyStd) MarshalPKCS1PublicKey() []byte {
	return x509.MarshalPKCS1PublicKey(pub.k)
}
