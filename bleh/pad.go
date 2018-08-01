package bleh

const PadLen = 8

type Pad [PadLen]byte

func (p Pad) apply(data []byte) {
	for i := range data {
		data[i] ^= p[i%PadLen]
	}
}
