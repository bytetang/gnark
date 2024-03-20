package rlc

import "github.com/consensys/gnark/frontend"

type SubArray struct {
	nIn       int // hex length, for ethereum storage it's 32bytes
	maxSelect int // hex length, for ethereum storage it's 32bytes
	nInBits   int // log ceil max hex length
}

func NewSubArray(nIn int, maxSelect int, nInBits int) *SubArray {
	var rlp = &SubArray{}
	rlp.nIn = nIn
	rlp.maxSelect = maxSelect
	rlp.nInBits = nInBits

	return rlp
}

func (subArray *SubArray) SubArray(api frontend.API, in []frontend.Variable, from frontend.Variable, end frontend.Variable) ([]frontend.Variable, frontend.Variable) {
	// from <= end
	api.AssertIsLessOrEqual(from, end)

	// end <= nIn
	api.AssertIsLessOrEqual(end, subArray.nIn)

	// end - from <= maxSelect
	api.AssertIsLessOrEqual(api.Sub(end, from), subArray.maxSelect)

	outLength := api.Sub(end, from)

	n2b := api.ToBinary(from)

	var shifts [][]frontend.Variable
	for i := 0; i < subArray.nIn; i++ {
		shifts = append(shifts, make([]frontend.Variable, 7))
	}
	for i := 0; i < subArray.nInBits; i++ {
		for j := 0; j < subArray.nIn; j++ {
			if i == 0 {
				tmpIndex := (j + 1<<i) % subArray.nIn
				/// n2b.out[idx] * (in[tempIdx] - in[j]) + in[j]
				shifts[j][i] = api.Add(api.Mul(n2b[i], api.Sub(in[tmpIndex], in[j])), in[j])
			} else {
				prevIndex := i - 1
				tmpIndex := (j + 1<<i) % subArray.nIn
				// shifts[idx][j] <== n2b.out[idx] * (shifts[prevIdx][tempIdx] - shifts[prevIdx][j]) + shifts[prevIdx][j];
				shifts[j][i] = api.Add(api.Mul(n2b[i], api.Sub(shifts[tmpIndex][prevIndex], shifts[j][prevIndex])), shifts[j][prevIndex])
			}
		}
	}
	var output []frontend.Variable
	for i := 0; i < subArray.maxSelect; i++ {
		output = append(output, shifts[i][subArray.nInBits-1])
	}

	return output, outLength
}

func RlpArrayPrefix(api frontend.API, in [2]frontend.Variable) (frontend.Variable, frontend.Variable, frontend.Variable) {

	//    // if starts with < 'c', then invalid
	lt1 := HexLessThanCheck(api, in[0], 12)

	// if starts with == 'f'
	eq := api.IsZero(api.Sub(in[0], 15))

	lt2 := HexLessThanCheck(api, in[1], 8)

	//	    isBig <== eq.out * (1 - lt2.out);
	isBig := api.Mul(eq, api.Sub(1, lt2))

	//var prefixVal = 16 * in[0] + in[1];
	prefixVal := api.Add(api.Mul(16, in[0]), in[1])
	//isValid <== 1 - lt1.out;
	isValid := api.Sub(1, lt1)
	//signal lenTemp;
	//lenTemp <== 2 * (prefixVal - 16 * 12) + 2 * isBig * (16 * 12 - 16 * 15 - 7);

	lenTemp := api.Mul(2, api.Sub(prefixVal, 192))
	lenTemp = api.Add(lenTemp, api.Mul(2, isBig, -55))
	//prefixOrTotalHexLen <== isValid * lenTemp;
	prefixOrTotalHexLen := api.Mul(isValid, lenTemp)

	return isBig, prefixOrTotalHexLen, isValid
}

func ShiftLeft(api frontend.API, nIn int, minShift int, maxShift int, in []frontend.Variable, shift frontend.Variable) []frontend.Variable {

	shiftBits := LogCeil(maxShift - minShift)

	// shift operations, shifts[shiftBits][nIn]
	var shifts [][]frontend.Variable

	for i := 0; i < shiftBits; i++ {
		shifts = append(shifts, make([]frontend.Variable, nIn))
	}

	var out []frontend.Variable

	if minShift == maxShift {
		for i := 0; i < nIn; i++ {
			out = append(out, in[(i+minShift)%nIn])
		}
	} else {
		b := api.Sub(shift, minShift)
		bn := api.ToBinary(b, shiftBits)
		for idx := 0; idx < shiftBits; idx++ {
			if idx == 0 {
				for j := 0; j < nIn; j++ {
					var tempIdx = (j + minShift + (1 << idx)) % nIn
					var tempIdx2 = (j + minShift) % nIn
					shift0j := api.Sub(in[tempIdx], in[tempIdx2])
					shift0j = api.Add(api.Mul(bn[idx], shift0j), in[tempIdx2])
					shifts[0][j] = shift0j
				}
			} else {
				for j := 0; j < nIn; j++ {
					var prevIdx = idx - 1
					var tempIdx = (j + (1 << idx)) % nIn
					//shifts[idx][j] <== bn[idx] * (shifts[prevIdx][tempIdx] - shifts[prevIdx][j]) + shifts[prevIdx][j];
					shiftsij := api.Sub(shifts[prevIdx][tempIdx], shifts[prevIdx][j])
					shiftsij = api.Add(api.Mul(bn[idx], shiftsij), shifts[prevIdx][j])
					shifts[idx][j] = shiftsij
				}
			}
		}
		for i := 0; i < nIn; i++ {
			out = append(out, shifts[shiftBits-1][i])
		}
	}
	return out
}

func HexLessThanCheck(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Add(cmp(api, a, b, 4), 1))
}

func cmp(api frontend.API, a, b frontend.Variable, bound int) frontend.Variable {

	bi1 := api.ToBinary(a, 4)
	bi2 := api.ToBinary(b, 4)

	res := frontend.Variable(0)

	for i := bound - 1; i >= 0; i-- {

		iszeroi1 := api.IsZero(bi1[i])
		iszeroi2 := api.IsZero(bi2[i])

		i1i2 := api.And(bi1[i], iszeroi2)
		i2i1 := api.And(bi2[i], iszeroi1)

		n := api.Select(i2i1, -1, 0)
		m := api.Select(i1i2, 1, n)

		res = api.Select(api.IsZero(res), m, res)

	}

	return res
}

func ArrayEqual(api frontend.API, a []frontend.Variable, b []frontend.Variable, maxLength int, targetLength frontend.Variable) frontend.Variable {
	api.AssertIsLessOrEqual(maxLength, len(a))
	api.AssertIsLessOrEqual(maxLength, len(b))

	var matchSum []frontend.Variable
	for i := 0; i < maxLength; i++ {
		if i == 0 {
			matchSum = append(matchSum, Equal(api, a[i], b[i]))
		} else {
			matchSum = append(matchSum, api.Add(matchSum[i-1], Equal(api, a[i], b[i])))
		}
	}

	var input [][]frontend.Variable
	input = append(input, []frontend.Variable{0})
	for i := 0; i < maxLength; i++ {
		input[0] = append(input[0], matchSum[i])
	}

	multiplexer := Multiplexer(api, targetLength, 1, maxLength+1, input)
	return Equal(api, targetLength, multiplexer[0])
}

func Equal(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}

func LogCeil(n int) int {
	var nTemp = n
	for i := 0; i < 254; i++ {
		if nTemp == 0 {
			return i
		}
		nTemp = nTemp / 2
	}
	return 254
}
