package rlc

import (
	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

func RandLinearCoefficients(api frontend.API, n int, commitment frontend.Variable) (gammaVec []frontend.Variable, challenge frontend.Variable) {
	// [commitment**(n-1), commitment**(n-2) ... commitment, 1]
	var accMulGamma = frontend.Variable(1)
	for i := 0; i < n; i++ {
		if i == 0 {
			gammaVec = append(gammaVec, 1)
		} else {
			accMulGamma = api.Mul(accMulGamma, commitment)
			gammaVec = append(gammaVec, accMulGamma)
		}
	}
	return gammaVec, commitment
}

func RandLinearCombination(api frontend.API, gammas []frontend.Variable, vbs []frontend.Variable) frontend.Variable {
	if len(gammas) != len(vbs) {
		panic("coefficient count mismatch")
	}
	var res frontend.Variable = 0
	for i := range vbs {
		res = api.Add(res, api.Mul(gammas[i], vbs[i]))
	}
	return res
}

func Exp(api frontend.API, X, E frontend.Variable) frontend.Variable {
	const bitSize = bls12377_fr.Bits

	// specify constraints
	output := frontend.Variable(1)
	bits := bits.ToBinary(api, E, bits.WithNbDigits(bitSize))

	for i := 0; i < len(bits); i++ {
		if i != 0 {
			output = api.Mul(output, output)
		}
		multiply := api.Mul(output, X)
		output = api.Select(bits[len(bits)-1-i], multiply, output)
	}

	return output
}
