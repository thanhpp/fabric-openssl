// SPDX-License-Identifier: Apache-2.0

package bcy256

import (
	"encoding/asn1"
	"math/big"

	"github.com/hyperledger/fabric/pkg/ecc"
)

const (
	CurveName = "bcy256"
)

var (
	Curve          *ecc.CurveParams
	CurveHalfOrder *big.Int
	Seed           *big.Int
	OIDNamedCurves = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1}
)

func Init() {
	// init curve
	Curve = new(ecc.CurveParams)

	Curve.BitSize = 256
	Curve.P, _ = new(big.Int).SetString("0xF21D860022F6FCD43E1F53A2A2CFEFF7823BD5430E0000BFD7B22DFFE71B2F49", 0)
	Curve.N, _ = new(big.Int).SetString("0x306C4E0006FE3290D939772086F6633187FF35E883E434618BDD7BF21A9F91B9", 0)
	Curve.A, _ = new(big.Int).SetString("0xA8B8A1E70A28B7770D396A55163701C389CBDC72D616295689664AE93E58F4CE", 0)
	Curve.B, _ = new(big.Int).SetString("0x8445D72302DEF7C8827AEC9808111498AC6BBB9CAD948A68A5FF116A2C0285D1", 0)
	Curve.Gx, _ = new(big.Int).SetString("0xEC45179388F6E8E92E688A368F5D09E26D3129DEDCAC5C88EB6531B8B3272BE5", 0)
	Curve.Gy, _ = new(big.Int).SetString("0x2D611DE19E2CBCD3C5C27046056B9AEEBE2BAF5BD95E4871FCF1235BB3F0677E", 0)
	Curve.Name = CurveName

	// init deps
	CurveHalfOrder = new(big.Int).Rsh(Curve.N, 1)

	// rand seed
	Seed, _ = new(big.Int).SetString("0xEAF74EA5B6824EB94B2DA177E566DFE350C135C9C7A7980A8301BD6F0CC833AC", 0)
}
