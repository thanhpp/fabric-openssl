/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opensslw

import (
	"crypto/ecdsa"
	"math/big"

	mopenssl "github.com/microsoft/go-crypto-openssl/openssl"
	"github.com/microsoft/go-crypto-openssl/openssl/bbig"
	"github.com/microsoft/go-crypto-openssl/openssl/bbig/bridge"
)

func ECDSAVerify(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool {
	x := bbig.Enc(pub.X)
	y := bbig.Enc(pub.Y)

	mPub, err := mopenssl.NewPublicKeyECDSA(pub.Curve.Params().Name, x, y)
	if err != nil {
		return false
	}

	return bridge.VerifyECDSA(mPub, hash, r, s)
}
