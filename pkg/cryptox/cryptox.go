/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptox

import (
	"os"
	"strconv"

	"github.com/hyperledger/fabric/pkg/bcy256"
	"github.com/hyperledger/fabric/pkg/mopenssl"
)

const (
	envUseStd = "USE_STD"
)

var useStd bool

func init() {
	useStd, _ = strconv.ParseBool(os.Getenv(envUseStd))

	if useStd {
		return
	}

	if err := mopenssl.Init(); err != nil {
		panic(err)
	}

	bcy256.Init()
}
