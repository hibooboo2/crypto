package crypto

import (
	"math/rand"
	"testing"
)

func TestAES(t *testing.T) {
	msg := GetData(rand.Intn(10000))

	cipher, err := AESEncrypt(msg, []byte("j"))
	if err != nil {
		t.Fatal(err)
	}

	m, err := AESDecrypt(cipher, []byte("j"))
	if err != nil {
		t.Fatal(err)
	}

	if len(m) != len(msg) {
		t.Fatal("Decrypt failed")
	}

	for i := range m {
		if m[i] != msg[i] {
			t.Fatal("Decrpyted msg not = original")
		}
	}
}

func BenchmarkEncryptDecrypt(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		msg := GetData(rand.Intn(23423))

		b.StartTimer()
		cipher, err := AESEncrypt(msg, []byte("somekey"))
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}

		b.StartTimer()
		m, err := AESDecrypt(cipher, []byte("somekey"))
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		if m == nil {
			b.Error("Nil decrypted txt")
		}

	}
}
