/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/hyperledger/fabric/pkg/opensslw"
	"github.com/stretchr/testify/require"
)

type rsaPublicKeyASN struct {
	N *big.Int
	E int
}

func TestRSAPublicKey(t *testing.T) {
	lowLevelKey, err := opensslw.GenerateCryptoRSAKey(2048)
	require.NoError(t, err)
	oKey, err := opensslw.ConvertRSAPublicKey(&lowLevelKey.PublicKey)
	require.NoError(t, err)
	k := &rsaPublicKey{oKey}

	require.False(t, k.Symmetric())
	require.False(t, k.Private())

	k.pubKey = nil
	ski := k.SKI()
	require.Nil(t, ski)

	k.pubKey = oKey
	ski = k.SKI()
	raw, err := asn1.Marshal(rsaPublicKeyASN{N: k.pubKey.N, E: k.pubKey.E})
	require.NoError(t, err, "asn1 marshal failed")
	hash := sha256.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	require.Equal(t, ski, ski2, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	require.NoError(t, err)
	require.Equal(t, k, pk)

	bytes, err := k.Bytes()
	require.NoError(t, err)
	bytes2 := k.pubKey.MarshalPKCS1PublicKey()
	require.Equal(t, bytes2, bytes, "bytes are not computed in the right way.")

	_, err = (&rsaPublicKey{}).Bytes()
	require.EqualError(t, err, "Failed marshalling key. Key is nil.")
}
