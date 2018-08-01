package bleh

import (
	"crypto/sha256"
	"fmt"
)

func Hash(data []byte) []byte {
	h := sha256.New()
	_, err := h.Write(data)
	if err != nil {
		panic(err)
	}
	data = h.Sum(nil)
	if len(data) != 32 {
		panic(fmt.Errorf("Invalid key length"))
	}
	return data
}

func HashArr(data []byte) Key {
	data = Hash(data)
	var d [32]byte
	for i, v := range data {
		d[i] = v
	}
	return d
}

func inRange(i, shift, len int) int {
	r := 0
	r += i + (2 * len) + (shift % len)
	r = r % len
	return r
}

type TransFormer func(data []byte, undo bool)

func GetPad(v int64) Pad {
	p := [PadLen]byte{}
	for i := uint(0); i < PadLen; i++ {
		p[PadLen-1-i] = byte(v >> (i * PadLen))
	}
	return p
}

func GetPadFromCipher(cipher []byte) Pad {
	var p Pad
	tmp := cipher[len(cipher)-PadLen:]
	for i := 0; i < PadLen; i++ {
		p[i] = tmp[i]
	}
	return p
}
