package main

import (
	"RsaEx/util"

	"fmt"
)

var (
	bigContentNotForRsa = `TOP 10 FACTS ABOUT SHAKESPEARE!
Trivia Fact 1 - No one knows the actual birthday of Shakespeare!
Trivia Fact 2 - Anne Hathaway was eight years older than Shakespeare and three months pregnant when they got married!
Trivia Fact 3 - Many Shakespeare life facts are unknown - these are referred to as the Lost Years
Trivia Fact 4 - Shakespeare's Father, John was a money lender! He was accused in the Exchequer Court of Usury for lending money at the inflated rate of 20% and 25% Interest!
Trivia Fact 5 - William Arden, a relative of Shakespeare's mother Mary Arden, was arrested for plotting against Queen Elizabeth I, imprisoned in the Tower of London and executed!
Trivia Fact 6 - Shakespeare and his company built TWO Globe Theatres!
Trivia Fact 7 - Shakespeare never published any of his plays!
Trivia Fact 8 - Shakespeare and the Globe Actors were implicated in the Essex Rebellion of 1601!
Trivia Fact 9 - Many eminent Authors and Politicians do not believe that Shakespeare wrote his plays...
Trivia Fact 10 - Shakespeare's family were all illiterate!`

	myKey        string
	myPublicKey  string
	hisKey       string
	hisPublicKey string
)

func init() {
	myKey, myPublicKey = util.NewKeys()
	hisKey, hisPublicKey = util.NewKeys()
}

func main() {
	//I do
	sessionKey, _ := util.GenerateRandomString(32)
	encryptedContent := util.EncryptPlainBF(bigContentNotForRsa, sessionKey)
	encryptedSessionKey, keySignature := util.EncryptAndSignRsa(sessionKey, hisPublicKey, myKey)

	//send encryptedContent, encryptedSessionKey, keySignature

	//he does
	decryptedSessionKey, verified := util.DecryptAndVerifyRsa(encryptedSessionKey, keySignature, hisKey, myPublicKey)
	if verified {
		fmt.Println("Session key is verified")
		decryptedContent := util.DecryptPlainBF(encryptedContent, decryptedSessionKey)
		fmt.Println("Decrypted:", decryptedContent)
	} else {
		fmt.Println("Session key is NOT verified!")
	}

}
