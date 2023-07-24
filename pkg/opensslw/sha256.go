/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opensslw

import (
	"hash"

	"github.com/hyperledger/fabric/pkg/openssl"
)

type sha256Hash struct {
	internalSHA256 *openssl.SHA256Hash
}

func (s *sha256Hash) Write(p []byte) (n int, err error) {
	return s.internalSHA256.Write(p)
}

func (s *sha256Hash) Sum(b []byte) []byte {
	sum, _ := s.internalSHA256.Sum()
	return sum[:]
}

func (s *sha256Hash) Reset() {
	_ = s.internalSHA256.Reset()
}

func (s *sha256Hash) Size() int {
	return 32
}

func (s *sha256Hash) BlockSize() int {
	return 64
}

func NewSHA256() hash.Hash {
	sha256, _ := openssl.NewSHA256Hash()

	return &sha256Hash{sha256}
}
