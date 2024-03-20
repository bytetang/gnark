package rlc

import (
	"bytes"
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
	"strconv"
)

func GetLogRLPFromReceiptRLP(_ *big.Int, in, out []*big.Int) error {
	b0, b1 := in[0], in[1]
	h := new(big.Int).Add(new(big.Int).Mul(b0, big.NewInt(16)), b1)
	prefixLen := (int(h.Int64()) - 247) * 2
	prefixHex := in[2 : prefixLen+2]

	prefixHexLe := Flip(prefixHex)
	size := big.NewInt(0)
	base := big.NewInt(16)
	for i, p := range prefixHexLe {
		exponent := big.NewInt(int64(i))
		exp := new(big.Int).Exp(base, exponent, nil) // Calculate 16^i
		v := new(big.Int).Mul(p, exp)
		size = size.Add(size, v)
	}

	rlpDataStart := 2 + prefixLen
	totalLen := rlpDataStart + int(size.Uint64())*2
	rlpData := in[rlpDataStart:totalLen]

	out[0] = big.NewInt(int64(prefixLen))
	copy(out[1:3], in[0:2])
	copy(out[3:9], prefixHex)
	fmt.Println("totalLen:", totalLen)
	copy(out[9:totalLen+9], rlpData)
	return nil
}

func DecodeReceiptLogs(_ *big.Int, input, out []*big.Int) error {

	var perLogSize = int(input[0].Uint64())
	var maxLogsNum = int(input[1].Uint64())

	in := input[2:]
	var bs []byte
	for i := 0; i < len(in)/2; i++ {
		b := new(big.Int).Mul(in[i*2], big.NewInt(16))
		b = b.Add(b, in[i*2+1])
		bs = append(bs, byte(b.Uint64()))
	}

	var logs []types.Log
	reader := bytes.NewReader(bs)
	err := rlp.Decode(reader, &logs)
	if err != nil {
		return err
	}

	var maxLogs []*big.Int // 80*2048
	var logLen []*big.Int  // 80

	for i, log := range logs {
		//fmt.Printf("log i:%d, log:%v\n", i, log)
		logBytes := new(bytes.Buffer)
		err1 := log.EncodeRLP(logBytes)
		if err1 != nil {
			return fmt.Errorf("encode log i:%d failed", i)
		}
		//fmt.Printf("log i:%d: rlp: %x\n", i, logBytes)

		logHex := fmt.Sprintf("%x", logBytes)
		var logRlp [1024]*big.Int

		for l_i := 0; l_i < 1024; l_i++ {
			if l_i < len(logHex) {
				intValue, _ := strconv.ParseInt(string(logHex[l_i]), 16, 64)
				logRlp[l_i] = big.NewInt(intValue)
			} else {
				logRlp[l_i] = big.NewInt(0)
			}
		}
		maxLogs = append(maxLogs, logRlp[:]...)
		logLen = append(logLen, big.NewInt(int64(len(logHex))))
	}

	copy(out[0:maxLogsNum], logLen)
	copy(out[maxLogsNum:maxLogsNum*perLogSize], maxLogs)
	return nil
}

func DecodeRlpPrefix(_ *big.Int, in, out []*big.Int) error {
	rlpData := in[1:]
	prefixLen, _ := decodeRlpPrefix(rlpData)

	out[0] = big.NewInt(int64(prefixLen))
	prefix := rlpData[0:prefixLen]

	pad0Len := len(out) - 1 - prefixLen
	copy(out[1+pad0Len:], prefix)

	return nil
}

func decodeRlpPrefix(in []*big.Int) (prefixLen int, size uint64) {
	fmt.Println("inputs:", in)
	var bs []byte
	for i := 0; i < len(in)/2; i++ {
		b := new(big.Int).Mul(in[i*2], big.NewInt(16))
		b = b.Add(b, in[i*2+1])
		bs = append(bs, byte(b.Uint64()))
	}
	fmt.Printf("bs:%x\n", bs)

	reader := bytes.NewReader(bs)
	fmt.Println("first byte:", bs[0])

	stream := rlp.NewStream(reader, in[0].Uint64())
	kind, size, err := stream.Kind()

	if err != nil {
		return
	}

	switch kind {
	case rlp.List:
		if size > 55 {
			prefixLen = 2 + (int(bs[0])-247)*2
		} else {
			prefixLen = 2
		}
		break
	case rlp.String:
		if size > 55 {
			prefixLen = 2 + (int(bs[0]-183))*2
		} else {
			prefixLen = 2
		}
		break
	case rlp.Byte:
		prefixLen = 2
		break
	}

	fmt.Println("kind:", kind, ", size:", size, ", prefix:", prefixLen)
	return
}
