package crypto

import (
	"crypto/rsa"
	"math/rand"
	"testing"
	"time"
)

const runes = `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`

func GetData(n int) []byte {
	var msg []byte
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < n; i++ {
		msg = append(msg, byte(runes[rand.Intn(len(runes)-1)]))
	}
	return msg
}

func TestSignAndVerify(t *testing.T) {
	key, err := CreatePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}
	e := &Entity{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
	}

	msg := GetData(rand.Intn(10000))

	val, err := e.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	err = e.Verify(msg, val)
	if err != nil {
		t.Fatal(err)
	}

	err = e.Verify(msg[1:], val)
	if err == nil {
		t.Fatal("Verify succeded with invalid message")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	e, err := CreateNewEntity()
	if err != nil {
		t.Fatal(err)
		return
	}

	d, err := e.Encrypt([]byte("High mother"))
	if err != nil {
		t.Fatal(err)
		return
	}

	val, err := e.Decrypt(d)
	if err != nil {
		t.Fatal(err)
		return
	}

	if string(val) != "High mother" {
		t.Fatal("failed to decrypt")
	}
}

var k *rsa.PrivateKey

func BenchmarkCreatePrivateKey(b *testing.B) {
	b.StopTimer()
	var err error
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		k, err = CreatePrivateKey()
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
	}
}
