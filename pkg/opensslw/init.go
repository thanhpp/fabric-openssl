/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opensslw

import (
	mopenssl "github.com/microsoft/go-crypto-openssl/openssl"
)

func init() {
	if err := mopenssl.Init(); err != nil {
		panic(err)
	}
}
