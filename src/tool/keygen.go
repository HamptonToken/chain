package main

import (
    "fmt"
    "encoding/base64"
    "github.com/tendermint/tendermint/crypto/ed25519"
    _ "github.com/tendermint/tendermint/crypto"
    _ "encoding/json"
)

func main() {
	mykey := ed25519.GenPrivKey()
	fmt.Println("private key:", mykey)
	privArray := [64]byte(mykey)
	privBytes := privArray[:]
	privB64 := base64.StdEncoding.EncodeToString(privBytes)
	fmt.Printf("private key base64: %s\n", privB64)

	fmt.Println("public key:", mykey.PubKey())
	fmt.Println("public key Bytes:", mykey.PubKey().Bytes())
	fmt.Println("address:", mykey.PubKey().Address())

	/* sign and verify */
	encrypted_result, _ := mykey.Sign([]byte("123"))
	fmt.Println("encrypted_result:")
	fmt.Println(encrypted_result)
	bb := mykey.PubKey().VerifyBytes([]byte("123"), encrypted_result)
	if bb == false {
		fmt.Println("the private key and public key have problem. please try again.")
	}
}
