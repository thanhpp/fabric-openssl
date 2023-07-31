/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptox

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/hyperledger/fabric/pkg/mopenssl"
)

func AESNewCipher(key []byte) (cipher.Block, error) {
	if useStd {
		return aes.NewCipher(key)
	}

	return mopenssl.NewAESCipher(key)
}
