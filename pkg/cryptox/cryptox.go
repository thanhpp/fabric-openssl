/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptox

import (
	"crypto/elliptic"
	"os"
	"strconv"

	"github.com/hyperledger/fabric/pkg/bcy256"
	"github.com/hyperledger/fabric/pkg/mopenssl"
)

const (
	envUseStd     = "USE_STD"
	defaultUseStd = true
)

var useStd bool

var Curve = elliptic.P256()

func init() {
	if val := os.Getenv(envUseStd); len(val) == 0 {
		useStd = defaultUseStd
	} else {
		useStd, _ = strconv.ParseBool(val)
	}

	if useStd {
		return
	}

	if err := mopenssl.Init(); err != nil {
		panic(err)
	}

	bcy256.Init()
}
