package rlc

import "github.com/consensys/gnark/frontend"

func Flip[T any](in []T) []T {
	res := make([]T, len(in))
	copy(res, in)
	for i := 0; i < len(in)/2; i++ {
		tmp := res[i]
		res[i] = res[len(res)-1-i]
		res[len(res)-1-i] = tmp
	}
	return res
}

func Multiplexer(
	api frontend.API,
	selector frontend.Variable,
	wIn int,
	nIn int,
	input [][]frontend.Variable,
) (output []frontend.Variable) {

	decoder, outputSuccess := Decoder(api, nIn, selector)
	for i := 0; i < wIn; i++ {
		ep := EscalarProduct(api, nIn, input[i], decoder)
		output = append(output, ep)
	}

	api.AssertIsEqual(outputSuccess, 1)
	return
}

func Decoder(api frontend.API, width int, input frontend.Variable) (output []frontend.Variable, outputSuccess frontend.Variable) {
	outputSuccess = 0
	for i := 0; i < width; i++ {
		value := Equal(api, i, input)
		output = append(output, value)
		outputSuccess = api.Add(outputSuccess, value)
	}
	api.AssertIsBoolean(outputSuccess)
	return
}

func EscalarProduct(api frontend.API, width int, inputA []frontend.Variable, inputB []frontend.Variable) (output frontend.Variable) {
	output = 0
	for i := 0; i < width; i++ {
		output = api.Add(output, api.Mul(inputA[i], inputB[i]))
	}
	return
}
