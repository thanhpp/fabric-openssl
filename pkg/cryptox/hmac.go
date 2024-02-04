/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptox

import (
	"crypto/hmac"
	"hash"

	"github.com/hyperledger/fabric/pkg/mopenssl"
)

func HMACSum(h func() hash.Hash, key []byte, data []byte) []byte {
	if useStd {
		return hmac.New(h, key).Sum(data)
	}

	newHash := h()
	blockSize := newHash.BlockSize()
	checkSumSize := newHash.Size()

	switch {
	// sha256.New
	case blockSize == 64 && checkSumSize == 32:
		h = mopenssl.NewSHA256
	// sha512.New384
	case blockSize == 128 && checkSumSize == 48:
		h = mopenssl.NewSHA384
	// sha3.New256
	case blockSize == 136 && checkSumSize == 32:
		h = mopenssl.NewSHA256
		// sha3.New384
	case blockSize == 104 && checkSumSize == 48:
		h = mopenssl.NewSHA384
	}

	// can be panic if h is not recognizable
	return mopenssl.NewHMAC(h, key).Sum(data)
}
