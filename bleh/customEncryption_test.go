package bleh

import (
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"testing"
	"time"
)

func TestEncryptDecrypt(t *testing.T) {
	var matched int
	runs := 1000
	for i := 0; i < runs; i++ {
		data := GetData(rand.Intn(4000))
		key := HashArr(GetData(100))

		cipher, err := key.Encrypt(data)
		if err != nil {
			t.Fatal(err)
		}

		val, err := key.Decrypt(cipher)
		if err != nil {
			t.Fatal(err)
		}

		if string(data) == string(cipher) {
			t.Error("cipher and data same")
		}
		if string(data) != string(val) {
			// t.Fatal(string(data), "\n", string(val))
			continue
		}
		matched++

	}
	if matched != runs {
		t.Fatalf("Failed to decrypt all values %d/%d", matched, runs)
	}
	t.Log("All encryptions / decryptions succeeded")
}

const runes = `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`

func GetData(n int) []byte {
	var msg []byte
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < n; i++ {
		msg = append(msg, byte(runes[rand.Intn(len(runes)-1)]))
	}
	return msg
}

func TestDifferntKeys(t *testing.T) {
	data := GetData(34)
	key := HashArr(GetData(22))
	cipher, err := key.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}

	key2 := HashArr(GetData(22))
	val, err := key2.Decrypt(cipher)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) == string(cipher) {
		t.Fatal("cipher and data same")
	}
	if string(data) == string(val) {
		t.Fatal("Values should not match")
	}
}

func TestCipherIsDifferentEnoughSameKey(t *testing.T) {
	data := GetData(100)
	key := HashArr(GetData(22))
	cipher, err := key.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}
	cipher2, err := key.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}
	var diff int
	for i := range cipher {
		if cipher[i] != cipher2[i] {
			diff++
		}
	}
	if diff < len(cipher)/10 {
		t.Fatalf("Not enough diffence between ciphers diff:%d min:%d", diff, len(cipher))
	}
}

func TestXOR(t *testing.T) {
	var b, c, q, r byte
	for i := 0; i < 256; i++ {
		b = byte(i)
		for j := 0; j < 256; j++ {
			c = byte(j)
			q = b ^ c
			r = q ^ c
			if r != b {
				t.Error(b, c, q, r)
			}
		}
	}
}

func TestShuffle(t *testing.T) {
	runs := 1000
	var passed int
	for i := 0; i < runs; i++ {
		d := GetData(100)
		orig := string(d)

		k := HashArr(GetData(100))
		k.shuffle(d, false)
		shuf := string(d)
		k.shuffle(d, true)
		unshuf := string(d)
		switch {
		case orig != unshuf:
		case shuf == unshuf || shuf == orig:
		default:
			passed++
		}
	}
	if passed != runs {
		t.Errorf("Not all shuffles passed: %d/%d", passed, runs)
	}
}

func TestPad(t *testing.T) {
	v := time.Now().UnixNano()
	p := GetPad(v)
	val := fmt.Sprintf("%064b", v)
	var buff bytes.Buffer
	for _, v := range p {
		fmt.Fprintf(&buff, "%08b", v)
	}
	if val != buff.String() {
		t.Fatal("Vals not same: ", val, buff.String())
	}
}

func TestGetPadFromCipher(t *testing.T) {
	p := GetPad(time.Now().UnixNano())
	d := GetData(22)
	d = append(d, p[:]...)
	p2 := GetPadFromCipher(d)

	for i := range p {
		if p[i] != p2[i] {
			t.Error("bytes do not match for pad")
		}
	}

}

func DiffBytes(a, b []byte) {
	diff := 0.00
	for i := range a {
		if a[i] != b[i] {
			diff++
		}
	}
	log.Printf("%0.f/%d %0.2f\n", diff, len(a), diff/float64(len(a)))
}
