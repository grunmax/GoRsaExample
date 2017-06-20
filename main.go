package main

import (
	"RsaEx/util"

	"fmt"
)

var (
	message = "Go to the app folder and execute go build there."
)

func main() {

	myKey, myPublicKey := util.NewKeyS()
	hisKey, hisPublicKey := util.NewKeyS()

	//	fmt.Println("Private Key : ", myKey)
	//	fmt.Println("Public key :", myPublicKey)
	//	fmt.Println("Private Key : ", hisKey)
	//	fmt.Println("Public key ", hisPublicKey)

	fmt.Println("Original message:", message)
	//I do
	ciphertext, signature := util.EncryptAndSignRsa(message, hisPublicKey, myKey)
	//	fmt.Println("Encrypted:", ciphertext)
	//	fmt.Println("Signature:", signature)

	//send ciphertext&signature

	//he does
	plainText, verified := util.DecryptAndVerifyRsa(ciphertext, signature, hisKey, myPublicKey)
	fmt.Println("Decrypted message:", plainText)
	fmt.Println("Verified:", verified)

}
