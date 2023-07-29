/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptox

import (
	"crypto/aes"
	"crypto/cipher"

	mopenssl "github.com/microsoft/go-crypto-openssl/openssl"
)

func AESNewCipher(key []byte) (cipher.Block, error) {
	if useStd {
		return aes.NewCipher(key)
	}

	return mopenssl.NewAESCipher(key)
}
