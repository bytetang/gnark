package rlc

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/multicommit"
	"github.com/consensys/gnark/test"
	"strconv"
	"testing"
)

type ReceiptRlp struct {
	ReceiptRlp    [4096]frontend.Variable
	maxReceiptLen int
}

func (c *ReceiptRlp) Define(api frontend.API) error {
	var in []frontend.Variable
	in = append(in, c.maxReceiptLen)
	in = append(in, c.ReceiptRlp[:]...)
	fmt.Println("maxReceiptLen:", c.maxReceiptLen)
	fmt.Println("receipt rlp:", c.ReceiptRlp)
	res, err := api.Compiler().NewHint(DecodeRlpPrefix, c.maxReceiptLen+1, in...)

	if err != nil {
		return err
	}
	api.Println(res[:]...)

	return nil
}

func TestRlpDecode(t *testing.T) {

	var receiptRlpHex = "f9047d0183431003b9010000000002400000000000000000000000000000000000000000000000000800001000000000000000000000000000000002000000080020000000000000200000000000000000000808000008000001000000000000000000000000008000008000000000000000000000100000000000000000000000000000000010000800000000002000000000000000000000000400000001010000000000000000000000020200000000200000000000800000000000000000000000000000000000040000010002000000000000000000000000000000000000000000000000000000000010200000000000000004000000000000010000000000400000000000000000f90372f87a94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f842a0e1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109ca0000000000000000000000000f9c814da15db75f7857898bad52df7404539c4e7a0000000000000000000000000000000000000000000000000005848f17eab2000f89b94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f863a08c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925a0000000000000000000000000f9c814da15db75f7857898bad52df7404539c4e7a0000000000000000000000000e592427a0aece92de3edee1f18e0157c05861564a0000000000000000000000000000000000000000000000000005848f17eab2000f89b94a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa00000000000000000000000008ad599c3a0ff1de082011efddc58f1908eb6e6d8a00000000000000000000000008df6872be6e53a2ace98b8c4411e052533efa637a000000000000000000000000000000000000000000000000000000000026872b1f89b94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000f9c814da15db75f7857898bad52df7404539c4e7a00000000000000000000000008ad599c3a0ff1de082011efddc58f1908eb6e6d8a0000000000000000000000000000000000000000000000000005848f17eab2000f9011c948ad599c3a0ff1de082011efddc58f1908eb6e6d8f863a0c42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67a0000000000000000000000000e592427a0aece92de3edee1f18e0157c05861564a00000000000000000000000008df6872be6e53a2ace98b8c4411e052533efa637b8a0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffd978d4f000000000000000000000000000000000000000000000000005848f17eab200000000000000000000000000000000000000060bc1ad254b8eb538115110c74aa000000000000000000000000000000000000000000000000396d6ea1458102210000000000000000000000000000000000000000000000000000000000031671"

	var receiptRlp [4096]frontend.Variable
	copy(receiptRlp[:], getHexArray(receiptRlpHex, 4096))

	var circuit, assigment ReceiptRlp

	circuit.maxReceiptLen = 4096
	assigment.maxReceiptLen = 4096
	assigment.ReceiptRlp = receiptRlp

	err := test.IsSolved(&circuit, &assigment, ecc.BLS12_377.ScalarField())
	assert := test.NewAssert(t)
	assert.NoError(err)

	//receiptRlp := hexutil.MustDecode(receiptRlpHex)
	//reader := bytes.NewReader(receiptRlp)
	//var receipt types.Receipt
	//err := rlp.Decode(reader, &receipt)
	//
	//assert := test.NewAssert(t)
	//assert.NoError(err)
	//
	//fmt.Println("receipt:", receipt)
	//
	//fmt.Printf("logs:%v\n", receipt.Logs)

}

func getHexArray(hexStr string, maxLen int) (res []frontend.Variable) {
	for i := 0; i < maxLen; i++ {
		if i < len(hexStr) {
			intValue, _ := strconv.ParseInt(string(hexStr[i]), 16, 64)
			res = append(res, intValue)
		} else {
			res = append(res, 0)
		}
	}
	return
}

type RLCPadWithPad struct {
	A    [6]frontend.Variable
	B    [6]frontend.Variable
	C    [7]frontend.Variable
	ALen frontend.Variable
	BLen frontend.Variable
}

func (c *RLCPadWithPad) Define(api frontend.API) error {
	multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		coefficients_a, _ := RandLinearCoefficients(api, 6, commitment)
		rlc_a := RandLinearCombination(api, coefficients_a, c.A[:])

		coefficients_b, _ := RandLinearCoefficients(api, 6, commitment)
		rlc_b := RandLinearCombination(api, coefficients_b, c.B[:])

		// r ** n_a
		r_exp_na := Exp(api, commitment, c.ALen)
		l := api.Add(api.Mul(rlc_b, r_exp_na), rlc_a)

		coefficients_c, _ := RandLinearCoefficients(api, 7, commitment)
		r := RandLinearCombination(api, coefficients_c, c.C[:])
		api.AssertIsEqual(l, r)
		return nil
	}, c.C[:]...)
	return nil
}

func TestRCLComputeWithPad(t *testing.T) {
	// c [1234abc]
	// a [123400]
	// b [abc000]

	var circuit, assignment RLCPadWithPad
	assignment.A = [6]frontend.Variable{1, 2, 3, 4, 0, 0}
	assignment.B = [6]frontend.Variable{10, 11, 12, 0, 0, 0}
	assignment.C = [7]frontend.Variable{1, 2, 3, 4, 10, 11, 12}
	assignment.ALen = 4
	assignment.BLen = 3

	err := test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert := test.NewAssert(t)
	assert.NoError(err)
}
