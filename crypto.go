package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/hibooboo2/p2pchat/transport"
	"github.com/segmentio/ksuid"
)

type UserList map[string]transport.User

func Verify(u *transport.User) error {
	data := []byte(u.GetKUID())
	data = append(data, u.GetPubKey()...)
	data = append(data, []byte(u.GetUsername())...)
	pub, err := x509.ParsePKCS1PublicKey(u.GetPubKey())
	if err != nil {
		return err
	}
	e := &Entity{PublicKey: pub}
	return e.Verify(data, u.GetSig())
}

type Entity struct {
	*rsa.PrivateKey
	*rsa.PublicKey
	UID ksuid.KSUID
}

func CreateNewEntity() (*Entity, error) {
	key, err := CreatePrivateKey()
	if err != nil {
		return nil, err
	}
	e := &Entity{
		UID:        ksuid.New(),
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
	}
	return e, nil
}

// ParsePrivateKey parses a PEM encoded private key.
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return rsa, nil
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}

func KeyData(k *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(k)
}

func CreatePrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	return privateKey, err
}

func (e *Entity) Encrypt(message []byte) ([]byte, error) {
	sha1 := sha1.New()

	encrypted, err := rsa.EncryptOAEP(sha1, rand.Reader, e.PublicKey, message, nil)
	if err != nil {
		return nil, err
	}
	return encrypted, err
}

func (e *Entity) Decrypt(data []byte) ([]byte, error) {
	sha1 := sha1.New()

	decrypted, err := rsa.DecryptOAEP(sha1, rand.Reader, e.PrivateKey, data, nil)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func (e *Entity) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, e.PrivateKey, crypto.SHA256, d)
}

func (e *Entity) Verify(message []byte, sig []byte) error {
	h := sha256.New()
	_, err := h.Write(message)
	if err != nil {
		return err
	}
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(e.PublicKey, crypto.SHA256, d, sig)
}
