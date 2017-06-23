package main

import (
	"RsaEx/util"

	"fmt"
)

var (
	content    = "It was noisy, crowded, bawdy, bustling and busy. Trades of every kind and description!"
	contentKey = "<Here is emailed contentKey>"
)

func main() {
	myKey, myPublicKey := util.NewKeys()
	hisKey, hisPublicKey := util.NewKeys()

	//	fmt.Println("Private Key : ", myKey)
	//	fmt.Println("Public key :", myPublicKey)
	//	fmt.Println("Private Key : ", hisKey)
	//	fmt.Println("Public key ", hisPublicKey)

	fmt.Println("Original:", contentKey)
	//I do
	ciphertext, signature := util.EncryptAndSignRsa(contentKey, hisPublicKey, myKey)
	//	fmt.Println("Encrypted:", ciphertext)
	//	fmt.Println("Signature:", signature)

	//send ciphertext&signature

	//he does
	plainText, verified := util.DecryptAndVerifyRsa(ciphertext, signature, hisKey, myPublicKey)
	fmt.Println("Decrypted:", plainText)
	fmt.Println("Verified:", verified)

}
