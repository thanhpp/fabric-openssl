/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opensslw

import (
	"hash"

	mopenssl "github.com/microsoft/go-crypto-openssl/openssl"
)

func NewSHA384() hash.Hash {
	return mopenssl.NewSHA384()
}
