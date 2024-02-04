/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptox

import (
	"crypto"
	"crypto/sha256"
	"hash"

	"github.com/hyperledger/fabric/pkg/mopenssl"
)

func SHA256(p []byte) (sum [32]byte) {
	if useStd {
		return sha256.Sum256(p)
	}

	return mopenssl.SHA256(p)
}

func NewSHA256() hash.Hash {
	if useStd {
		return crypto.SHA256.New()
	}

	return mopenssl.NewSHA256()
}

func NewSHA384() hash.Hash {
	if useStd {
		return crypto.SHA384.New()
	}

	return mopenssl.NewSHA384()
}
