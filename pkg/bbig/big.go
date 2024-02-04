/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// This is a mirror of crypto/internal/boring/bbig/big.go.

package bbig

import (
	"math/big"
	"unsafe"

	"github.com/hyperledger/fabric/pkg/mopenssl"
)

func Enc(b *big.Int) mopenssl.BigInt {
	if b == nil {
		return nil
	}
	x := b.Bits()
	if len(x) == 0 {
		return mopenssl.BigInt{}
	}
	// TODO: Use unsafe.Slice((*uint)(&x[0]), len(x)) once go1.16 is no longer supported.
	return (*(*[]uint)(unsafe.Pointer(&x)))[:len(x)]
}

func Dec(b mopenssl.BigInt) *big.Int {
	if b == nil {
		return nil
	}
	if len(b) == 0 {
		return new(big.Int)
	}
	// TODO: Use unsafe.Slice((*uint)(&b[0]), len(b)) once go1.16 is no longer supported.
	x := (*(*[]big.Word)(unsafe.Pointer(&b)))[:len(b)]
	return new(big.Int).SetBits(x)
}
