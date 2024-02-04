/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sw

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/pkg/cryptox"
)

type ecdsaPublicKeyKeyDeriver struct{}

func (kd *ecdsaPublicKeyKeyDeriver) KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	// Validate opts
	if opts == nil {
		return nil, errors.New("Invalid opts parameter. It must not be nil.")
	}

	ecdsaK := key.(*ecdsaPublicKey)

	// Re-randomized an ECDSA private key
	reRandOpts, ok := opts.(*bccsp.ECDSAReRandKeyOpts)
	if !ok {
		return nil, fmt.Errorf("Unsupported 'KeyDerivOpts' provided [%v]", opts)
	}

	tempSK := &ecdsa.PublicKey{
		Curve: ecdsaK.pubKey.Curve(),
		X:     new(big.Int),
		Y:     new(big.Int),
	}
	k := new(big.Int).SetBytes(reRandOpts.ExpansionValue())
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(ecdsaK.pubKey.Curve().Params().N, one)
	k.Mod(k, n)
	k.Add(k, one)

	// Compute temporary public key
	tempX, tempY := ecdsaK.pubKey.Curve().ScalarBaseMult(k.Bytes())
	tempSK.X, tempSK.Y = tempSK.Curve.Add(
		ecdsaK.pubKey.X(), ecdsaK.pubKey.Y(),
		tempX, tempY,
	)

	// Verify temporary public key is a valid point on the reference curve
	isOn := tempSK.Curve.IsOnCurve(tempSK.X, tempSK.Y)
	if !isOn {
		return nil, errors.New("Failed temporary public key IsOnCurve check.")
	}

	pubKey, err := cryptox.NewECDSAPublicKey(tempSK.Curve, tempSK.X, tempSK.Y)
	if err != nil {
		return nil, fmt.Errorf("new ecdsa public key error: %w", err)
	}

	return &ecdsaPublicKey{pubKey}, nil
}

type ecdsaPrivateKeyKeyDeriver struct{}

func (kd *ecdsaPrivateKeyKeyDeriver) KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	// Validate opts
	if opts == nil {
		return nil, errors.New("Invalid opts parameter. It must not be nil.")
	}

	ecdsaK := key.(*ecdsaPrivateKey)

	// Re-randomized an ECDSA private key
	reRandOpts, ok := opts.(*bccsp.ECDSAReRandKeyOpts)
	if !ok {
		return nil, fmt.Errorf("Unsupported 'KeyDerivOpts' provided [%v]", opts)
	}

	tempSK := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: ecdsaK.privKey.Curve(),
			X:     new(big.Int),
			Y:     new(big.Int),
		},
		D: new(big.Int),
	}

	k := new(big.Int).SetBytes(reRandOpts.ExpansionValue())
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(ecdsaK.privKey.Curve().Params().N, one)
	k.Mod(k, n)
	k.Add(k, one)

	tempSK.D.Add(ecdsaK.privKey.D(), k)
	tempSK.D.Mod(tempSK.D, ecdsaK.privKey.Curve().Params().N)

	// Compute temporary public key
	tempX, tempY := ecdsaK.privKey.Curve().ScalarBaseMult(k.Bytes())
	tempSK.X, tempSK.Y =
		tempSK.Curve.Add(
			ecdsaK.privKey.X(), ecdsaK.privKey.Y(),
			tempX, tempY,
		)

	// Verify temporary public key is a valid point on the reference curve
	isOn := tempSK.Curve.IsOnCurve(tempSK.X, tempSK.Y)
	if !isOn {
		return nil, errors.New("Failed temporary public key IsOnCurve check.")
	}

	privK, err := cryptox.NewECDSAPrivateKey(tempSK.Curve, tempSK.X, tempSK.Y, tempSK.D)
	if err != nil {
		return nil, fmt.Errorf("new ecdsa private key error: %w", err)
	}

	return &ecdsaPrivateKey{privK}, nil
}

type aesPrivateKeyKeyDeriver struct {
	conf *config
}

func (kd *aesPrivateKeyKeyDeriver) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	// Validate opts
	if opts == nil {
		return nil, errors.New("Invalid opts parameter. It must not be nil.")
	}

	aesK := k.(*aesPrivateKey)

	switch hmacOpts := opts.(type) {
	case *bccsp.HMACTruncated256AESDeriveKeyOpts:
		sum := cryptox.HMACSum(kd.conf.hashFunction, aesK.privKey, hmacOpts.Argument())
		return &aesPrivateKey{sum[:kd.conf.aesBitLength], false}, nil

	case *bccsp.HMACDeriveKeyOpts:
		sum := cryptox.HMACSum(kd.conf.hashFunction, aesK.privKey, hmacOpts.Argument())
		return &aesPrivateKey{sum, true}, nil

	default:
		return nil, fmt.Errorf("Unsupported 'KeyDerivOpts' provided [%v]", opts)
	}
}
