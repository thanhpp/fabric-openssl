/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/hyperledger/fabric/pkg/cryptox"
	"github.com/stretchr/testify/require"
)

func TestSignECDSABadParameter(t *testing.T) {
	// Generate a key
	lowLevelKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Induce an error on the underlying ecdsa algorithm
	curve := *elliptic.P256().Params()
	curve.N = big.NewInt(0)
	lowLevelKey.Curve = &curve

	_, err = signECDSA(lowLevelKey, []byte("hello world"), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "zero parameter")
}

func TestVerifyECDSA(t *testing.T) {
	t.Parallel()

	// Generate a key
	// lowLevelKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// require.NoError(t, err)
	lowLevelKey, err := cryptox.GenECDSAPrivateKey(elliptic.P256())
	require.NoError(t, err)

	msg := []byte("hello world")
	sigma, err := lowLevelKey.Sign(msg)
	require.NoError(t, err)

	valid, err := verifyECDSA(lowLevelKey.Public(), sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)

	R, S, err := utils.UnmarshalECDSASignature(sigma)
	require.NoError(t, err)

	t.Logf(
		"TestVerifyECDSA\ninput: %v\nsigma %v\nsigma_R: %v\nsigma_s: %v\nverify_success: %t",
		msg, sigma, R.Bytes(), S.Bytes(), valid,
	)

	_, err = verifyECDSA(lowLevelKey.Public(), nil, msg, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed unmashalling signature [")

	S.Add(utils.GetCurveHalfOrdersAt(elliptic.P256()), big.NewInt(1))
	sigmaWrongS, err := utils.MarshalECDSASignature(R, S)
	require.NoError(t, err)
	_, err = verifyECDSA(lowLevelKey.Public(), sigmaWrongS, msg, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid S. Must be smaller than half the order [")
}

func TestEcdsaSignerSign(t *testing.T) {
	t.Parallel()

	signer := &ecdsaSigner{}
	verifierPrivateKey := &ecdsaPrivateKeyVerifier{}
	verifierPublicKey := &ecdsaPublicKeyKeyVerifier{}

	// Generate a key
	// lowLevelKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// require.NoError(t, err)
	lowLevelKey, err := cryptox.GenECDSAPrivateKey(elliptic.P256())
	require.NoError(t, err)
	k := &ecdsaPrivateKey{lowLevelKey}
	pk, err := k.PublicKey()
	require.NoError(t, err)

	// Sign
	msg := []byte("Hello World")
	sigma, err := signer.Sign(k, msg, nil)
	require.NoError(t, err)
	require.NotNil(t, sigma)
	t.Logf("TestEcdsaSignerSign, msg: %s, sigma: %+v, hexSigma: %s", string(msg), sigma, hex.EncodeToString(sigma))

	// Verify
	valid, err := verifyECDSA(lowLevelKey.Public(), sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)

	valid, err = verifierPrivateKey.Verify(k, sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)

	valid, err = verifierPublicKey.Verify(pk, sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestEcdsaPrivateKey(t *testing.T) {
	t.Parallel()

	// lowLevelKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// require.NoError(t, err)
	lowLevelKey, err := cryptox.GenECDSAPrivateKey(elliptic.P256())
	require.NoError(t, err)
	k := &ecdsaPrivateKey{lowLevelKey}

	require.False(t, k.Symmetric())
	require.True(t, k.Private())

	_, err = k.Bytes()
	require.Error(t, err)
	require.Contains(t, err.Error(), "Not supported.")

	k.privKey = nil
	ski := k.SKI()
	require.Nil(t, ski)

	k.privKey = lowLevelKey
	ski = k.SKI()
	raw := elliptic.Marshal(k.privKey.Curve(), k.privKey.X(), k.privKey.Y())
	hash := sha256.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	require.Equal(t, ski2, ski, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	require.NoError(t, err)
	require.NotNil(t, pk)

	ecdsaPK, ok := pk.(*ecdsaPublicKey)
	require.True(t, ok)
	require.Equal(t, lowLevelKey.Public(), ecdsaPK.pubKey)
}

func TestEcdsaPublicKey(t *testing.T) {
	t.Parallel()

	// lowLevelKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// require.NoError(t, err)
	lowLevelKey, err := cryptox.GenECDSAPrivateKey(elliptic.P256())
	require.NoError(t, err)
	k := &ecdsaPublicKey{lowLevelKey.Public()}

	require.False(t, k.Symmetric())
	require.False(t, k.Private())

	k.pubKey = nil
	ski := k.SKI()
	require.Nil(t, ski)

	k.pubKey = lowLevelKey.Public()
	ski = k.SKI()
	raw := elliptic.Marshal(k.pubKey.Curve(), k.pubKey.X(), k.pubKey.Y())
	hash := sha256.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	require.Equal(t, ski, ski2, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	require.NoError(t, err)
	require.Equal(t, k, pk)

	bytes, err := k.Bytes()
	require.NoError(t, err)
	bytes2, err := k.pubKey.MarshalPKIXPublicKey()
	require.NoError(t, err)
	require.Equal(t, bytes2, bytes, "bytes are not computed in the right way.")

	invalidCurve := &elliptic.CurveParams{Name: "P-Invalid"}
	invalidCurve.P = big.NewInt(1)
	invalidCurve.N = big.NewInt(1)
	invalidCurve.B = big.NewInt(1)
	invalidCurve.BitSize = 1024
	// require error here because NewECDSAPublicKey don't accept invalid curve
	_, err = cryptox.NewECDSAPublicKey(invalidCurve, big.NewInt(1), big.NewInt(1))
	require.Error(t, err)

	// defer func() {
	// 	if r := recover(); r != nil {
	// 		require.Contains(t, r, "crypto/elliptic: attempted operation on invalid point")
	// 	}
	// }()
	// _, err = k.Bytes()
	// require.Error(t, err)
	// require.Contains(t, err.Error(), "Failed marshalling key [")
}
