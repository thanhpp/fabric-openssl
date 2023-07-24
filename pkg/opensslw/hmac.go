/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opensslw

import (
	"fmt"
	"hash"

	"github.com/hyperledger/fabric/pkg/openssl"
)

func NewHMAC(h func() hash.Hash, key []byte) (*openssl.HMAC, error) {
	newHash := h()
	blockSize := newHash.BlockSize()
	checkSumSize := newHash.Size()

	/* available h
	sha256.New
	sha512.New384
	sha3.New256
	sha3.New384
	*/

	switch {
	// sha256.New
	case blockSize == 64 && checkSumSize == 32:
		return openssl.NewHMAC(key, openssl.EVP_SHA256)
	// sha512.New384
	case blockSize == 128 && checkSumSize == 48:
		return openssl.NewHMAC(key, openssl.EVP_SHA384)
	// sha3.New256
	case blockSize == 136 && checkSumSize == 32:
		return openssl.NewHMAC(key, openssl.EVP_SHA256)
		// sha3.New384
	case blockSize == 104 && checkSumSize == 48:
		return openssl.NewHMAC(key, openssl.EVP_SHA384)
	default:
		return nil, fmt.Errorf("hash function not support, blockSize: %d, checkSumSize: %d", blockSize, checkSumSize)
	}
}
