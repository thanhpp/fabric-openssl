/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opensslw

import (
	"crypto/cipher"

	mopenssl "github.com/microsoft/go-crypto-openssl/openssl"
)

func AESNewCipher(key []byte) (cipher.Block, error) {
	return mopenssl.NewAESCipher(key)
}
