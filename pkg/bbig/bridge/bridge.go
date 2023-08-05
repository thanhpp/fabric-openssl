/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// These wrappers only exist for code reuse in places where we need the old pre-go1.19 signature.

package bridge

import (
	"encoding/asn1"
	"math/big"

	"github.com/hyperledger/fabric/pkg/bbig"
	"github.com/hyperledger/fabric/pkg/mopenssl"
)

func GenerateKeyECDSA(curve string) (X, Y, D *big.Int, err error) {
	x, y, d, err := mopenssl.GenerateKeyECDSA(curve)
	if err != nil {
		return nil, nil, nil, err
	}
	return bbig.Dec(x), bbig.Dec(y), bbig.Dec(d), nil
}

type ecdsaSignature struct {
	R, S *big.Int
}

func SignECDSA(priv *mopenssl.PrivateKeyECDSA, hash []byte) (r, s *big.Int, err error) {
	sig, err := mopenssl.SignMarshalECDSA(priv, hash)
	if err != nil {
		return nil, nil, err
	}
	var esig ecdsaSignature
	if _, err := asn1.Unmarshal(sig, &esig); err != nil {
		return nil, nil, err
	}
	return esig.R, esig.S, nil
}

func NewPrivateKeyECDSA(curve string, X, Y, D *big.Int) (*mopenssl.PrivateKeyECDSA, error) {
	return mopenssl.NewPrivateKeyECDSA(curve, bbig.Enc(X), bbig.Enc(Y), bbig.Enc(D))
}

func NewPublicKeyECDSA(curve string, X, Y *big.Int) (*mopenssl.PublicKeyECDSA, error) {
	return mopenssl.NewPublicKeyECDSA(curve, bbig.Enc(X), bbig.Enc(Y))
}

func VerifyECDSA(pub *mopenssl.PublicKeyECDSA, hash []byte, r, s *big.Int) bool {
	sig, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return false
	}
	return mopenssl.VerifyECDSA(pub, hash, sig)
}

func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv *big.Int, err error) {
	bN, bE, bD, bP, bQ, bDp, bDq, bQinv, err1 := mopenssl.GenerateKeyRSA(bits)
	if err1 != nil {
		err = err1
		return
	}
	N = bbig.Dec(bN)
	E = bbig.Dec(bE)
	D = bbig.Dec(bD)
	P = bbig.Dec(bP)
	Q = bbig.Dec(bQ)
	Dp = bbig.Dec(bDp)
	Dq = bbig.Dec(bDq)
	Qinv = bbig.Dec(bQinv)
	return
}

func NewPublicKeyRSA(N, E *big.Int) (*mopenssl.PublicKeyRSA, error) {
	return mopenssl.NewPublicKeyRSA(bbig.Enc(N), bbig.Enc(E))
}

func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv *big.Int) (*mopenssl.PrivateKeyRSA, error) {
	return mopenssl.NewPrivateKeyRSA(
		bbig.Enc(N), bbig.Enc(E), bbig.Enc(D),
		bbig.Enc(P), bbig.Enc(Q),
		bbig.Enc(Dp), bbig.Enc(Dq), bbig.Enc(Qinv),
	)
}
