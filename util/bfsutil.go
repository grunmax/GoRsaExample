package util

import (
	"crypto/rand"

	b64 "encoding/base64"

	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"
	"golang.org/x/crypto/blowfish"
)

func EncryptPlainBF(plain, key string) string {
	return b64.StdEncoding.EncodeToString(encryptBF([]byte(plain), []byte(key)))
}

func encryptBF(pt, key []byte) []byte {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	mode := ecb.NewECBEncrypter(block)
	padder := padding.NewPkcs5Padding()
	pt, err = padder.Pad(pt)
	if err != nil {
		panic(err.Error())
	}
	ct := make([]byte, len(pt))
	mode.CryptBlocks(ct, pt)
	return ct
}

func DecryptPlainBF(plain, key string) string {
	plaincipher, _ := b64.StdEncoding.DecodeString(plain)
	decrypted := decryptBF(plaincipher, []byte(key))
	return string(decrypted[:len(decrypted)])
}

func decryptBF(ct, key []byte) []byte {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	mode := ecb.NewECBDecrypter(block)
	pt := make([]byte, len(ct))
	mode.CryptBlocks(pt, ct)
	padder := padding.NewPkcs5Padding()
	pt, err = padder.Unpad(pt)
	if err != nil {
		panic(err.Error())
	}
	return pt
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-~!@#$%^&*()+=?"
	bytes, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}
	return string(bytes), nil
}
