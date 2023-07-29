/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptox

import (
	"os"
	"strconv"

	mopenssl "github.com/microsoft/go-crypto-openssl/openssl"
)

const (
	envUseStd = "USE_STD"
)

var (
	useStd bool
)

func init() {
	useStd, _ = strconv.ParseBool(os.Getenv(envUseStd))

	if useStd {
		return
	}

	if err := mopenssl.Init(); err != nil {
		panic(err)
	}
}
