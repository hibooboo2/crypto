package bleh

import (
	"math/rand"
	"time"
)

type Key [KeyLen]byte

const KeyLen = 32

func (k Key) shuffle(data []byte, undo bool) {
	r := rand.NewSource(k.getSeed())
	nums := make([]int, len(data))
	for i := range nums {
		nums[i] = int(r.Int63() % int64(len(data)))
	}

	if undo {
		for i := len(data) - 1; i >= 0; i-- {
			data[i], data[nums[i]] = data[nums[i]], data[i]
		}
	} else {
		for i := range data {
			data[i], data[nums[i]] = data[nums[i]], data[i]
		}
	}
}

func (k Key) getSeed() int64 {
	index := int(k[6]) % KeyLen
	x := int64(k[index])
	x = x << 8
	x += int64(k[6])
	x = x << 8
	x += int64(k[9])
	x = x << 8
	x += int64(k[13])
	return x
}

func (k Key) xorByte(cipher []byte, _ bool) {
	for i := range cipher {
		cipher[i] = cipher[i] ^ k[31]
	}
}

func (k Key) Encrypt(plaintext []byte) ([]byte, error) {
	cipher := make([]byte, len(plaintext))
	for i := range plaintext {
		cipher[i] = plaintext[i]
	}

	k.applyTransFormers(cipher, false)
	p := GetPad(time.Now().UnixNano())
	p.apply(cipher)
	return append(cipher, p[:]...), nil
}

func (k Key) Decrypt(cipher []byte) ([]byte, error) {
	val := make([]byte, len(cipher)-PadLen)

	for i := range val {
		val[i] = cipher[i]
	}

	p := GetPadFromCipher(cipher)
	p.apply(val)

	k.applyTransFormers(val, true)

	return val, nil
}

func (k Key) applyTransFormers(data []byte, undo bool) {
	trans := []TransFormer{
		k.xorByte,
		k.shuffle,
	}
	if undo {
		end := len(trans)
		tmp := make([]TransFormer, end)
		for i := range trans {
			tmp[end-1-i] = trans[i]
		}
		trans = tmp
	}

	for _, t := range trans {
		t(data, undo)
	}
}
