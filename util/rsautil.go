package util

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/gob"
	"fmt"
	"strconv"
)

var (
	keysize = 1024
	label   = []byte("some x-label")
)

func getPrivateKeyStr(key *rsa.PrivateKey) string {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	err := e.Encode(key)
	if err != nil {
		panic(err)
	}
	return b64.StdEncoding.EncodeToString(b.Bytes())
}

func getPublicKeyStr(key *rsa.PublicKey) string {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	err := e.Encode(key)
	if err != nil {
		panic(err)
	}
	return b64.StdEncoding.EncodeToString(b.Bytes())
}

func getPrivateKey(str string) *rsa.PrivateKey {
	m := rsa.PrivateKey{}
	by, err := b64.StdEncoding.DecodeString(str)
	if err != nil {
		fmt.Println(`failed base64 Decode`, err)
	}
	b := bytes.Buffer{}
	b.Write(by)
	d := gob.NewDecoder(&b)
	err = d.Decode(&m)
	if err != nil {
		fmt.Println(`failed gob Decode`, err)
	}
	return &m
}

func getPublicKey(str string) *rsa.PublicKey {
	m := rsa.PublicKey{}
	by, err := b64.StdEncoding.DecodeString(str)
	if err != nil {
		fmt.Println(`failed base64 Decode`, err)
	}
	b := bytes.Buffer{}
	b.Write(by)
	d := gob.NewDecoder(&b)
	err = d.Decode(&m)
	if err != nil {
		fmt.Println(`failed gob Decode`, err)
	}
	return &m
}

func GetMaxMessage() int {
	return ((keysize - 384) / 8) + 7
}

func NewKeyS() (string, string) {
	key := NewKey()
	pubkey := &key.PublicKey
	return getPrivateKeyStr(key), getPublicKeyStr(pubkey)
}

func NewKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, keysize)
	if err != nil {
		panic(err)
	}
	return key
}

func EncryptRsa(message string, key *rsa.PublicKey) []byte {
	messagebytes := []byte(message)
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, key, messagebytes, label)
	if err != nil {
		panic(err)
	}
	return ciphertext
}

func SignRsa(message string, key *rsa.PrivateKey) []byte {
	var opts rsa.PSSOptions
	messagebytes := []byte(message)
	opts.SaltLength = rsa.PSSSaltLengthAuto
	PSSmessage := messagebytes
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, key, newhash, hashed, &opts)
	if err != nil {
		panic(err)
	}
	return signature
}

func DecryptRsa(ciphertext []byte, key *rsa.PrivateKey) string {
	hash := sha256.New()
	decrypted, err := rsa.DecryptOAEP(hash, rand.Reader, key, ciphertext, label)
	if err != nil {
		panic(err)
	}
	return string(decrypted[:len(decrypted)])
}

func VerifyRsa(message string, signature []byte, key *rsa.PublicKey) bool {
	var opts rsa.PSSOptions
	messagebytes := []byte(message)
	opts.SaltLength = rsa.PSSSaltLengthAuto
	PSSmessage := messagebytes
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)
	err := rsa.VerifyPSS(key, newhash, hashed, signature, &opts)
	if err != nil {
		return false
	} else {
		return true
	}
}

func EncryptAndSignRsa(message string, key1_ string, key2_ string) (string, string) {
	key1 := getPublicKey(key1_)
	key2 := getPrivateKey(key2_)
	messagebytes := []byte(message)
	maxlen := GetMaxMessage()
	if len(messagebytes) > maxlen {
		panic("too big, message should be " + strconv.Itoa(maxlen))
	}
	hash := sha256.New()
	ciphertext_, err := rsa.EncryptOAEP(hash, rand.Reader, key1, messagebytes, label)
	if err != nil {
		panic(err)
	}
	ciphertext := b64.StdEncoding.EncodeToString([]byte(ciphertext_))

	// sign by my private key
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto
	PSSmessage := messagebytes
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	signature_, err := rsa.SignPSS(rand.Reader, key2, newhash, hashed, &opts)
	if err != nil {
		panic(err)
	}
	signature := b64.StdEncoding.EncodeToString([]byte(signature_))
	return ciphertext, signature
}

func DecryptAndVerifyRsa(ciphertext_ string, signature_ string, key1_ string, key2_ string) (string, bool) {
	ciphertext, _ := b64.StdEncoding.DecodeString(ciphertext_)
	signature, _ := b64.StdEncoding.DecodeString(signature_)
	key1 := getPrivateKey(key1_)
	key2 := getPublicKey(key2_)
	hash := sha256.New()
	messagebytes, err := rsa.DecryptOAEP(hash, rand.Reader, key1, ciphertext, label)
	if err != nil {
		panic(err)
	}
	message := string(messagebytes[:len(messagebytes)])

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto
	PSSmessage := messagebytes
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)
	err = rsa.VerifyPSS(key2, newhash, hashed, signature, &opts)
	var verified bool
	if err != nil {
		verified = false
	} else {
		verified = true
	}

	return message, verified
}
