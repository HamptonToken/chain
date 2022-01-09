/* 
    HAETA 2022
    generate base64 private key, 
        public key, address for users to save.
    then deserialze
*/

package main

import (
    "fmt"
    "encoding/base64"
    "encoding/hex"
    "github.com/tendermint/tendermint/crypto/ed25519"
    _ "github.com/tendermint/tendermint/crypto"
    _ "encoding/json"
    "reflect"
    "crypto/sha256"
)

const PubKeyEd25519Size = 32
const PrivKeyEd25519Size = 64
const PubkeyStart = "PubKeyEd25519{"

func main() {
	a, b, c := generate_keys()
	fmt.Println(a)
	fmt.Println(b)
	fmt.Println(c)

	priv, pub := deserilize(a, b)
	//fmt.Println(priv, pub)

	// sign and verify
	s256 := do_sha256([]byte("125"))
	encrypted_result, _ := priv.Sign([]byte(string(s256[:32])))
	fmt.Println("encrypted_result")
	fmt.Println(encrypted_result)

	// this base64 used for signature.
	fmt.Println("encrypted_result base64")
	encrypted_result_b64 := base64.StdEncoding.EncodeToString([]byte(encrypted_result))
	fmt.Println(encrypted_result_b64)
	bb := pub.VerifyBytes(s256[:32], encrypted_result)
        if bb {
		fmt.Println("private and publice key deserialize successfully.")
	} else {
		fmt.Println("private and publice key deserialize unsuccessfully.")
	}
	pDec, _ := base64.StdEncoding.DecodeString(encrypted_result_b64)
	fmt.Println("encrypted_result")
	fmt.Println(pDec)

	// test types
	//fmt.Printf("%T\n", encrypted_result)
	//fmt.Printf("%T\n", pDec)
	if reflect.DeepEqual(encrypted_result, pDec) == false { //can also use bytes.Equal
		fmt.Println("Error: encrypted_result_b64 deserialized wrong..")
	}
}

func do_sha256(input []byte) [32]byte{
	sum := sha256.Sum256([]byte(input))
	return sum
}

/* 
example output for priv_key, pub_key, address:
mB3bPsj9kUsAPmFw11Gqb6AYi7nQ8PFrNI+G62IRyYnstkObfl1KIeQi8pOfpNovC2iikxivhW9baCLStM2hyA==
7LZDm35dSiHkIvKTn6TaLwtoopMYr4VvW2gi0rTNocg=
0D9FE6A785C830D2BE66FE40E0E7FE3D9838456CE15D2C
*/
func generate_keys() (priv_key_base64, pub_key_base64, address string) {
	mykey := ed25519.GenPrivKey()
	privArray := [PrivKeyEd25519Size]byte(mykey)
	privBytes := privArray[:]
	privB64 := base64.StdEncoding.EncodeToString(privBytes)
	//fmt.Printf("private key base64: %s\n", privB64)
	priv_key_base64 = privB64

	mystr := fmt.Sprintf("%s", mykey.PubKey())
	mystr = mystr[len(PubkeyStart):len(PubkeyStart) + PrivKeyEd25519Size]

        src := []byte(mystr)
	dst := make([]byte, hex.DecodedLen(len(src)))
	n, err := hex.Decode(dst, src)
	if err != nil {
	    fmt.Println("decode err:", n, err)
	}

	pubB64 := base64.StdEncoding.EncodeToString([]byte(dst))
        //fmt.Printf("public key base64: %s\n", pubB64)
	pub_key_base64 = pubB64

	//fmt.Println("address:", mykey.PubKey().Address())
	address = fmt.Sprintf("%s", mykey.PubKey().Address())
	return
}

func deserilize(priv_key_b64, pub_key_b64 string) (ed25519.PrivKeyEd25519, ed25519.PubKeyEd25519){
	kDec, _ := base64.StdEncoding.DecodeString(priv_key_b64)
        pp := []byte(kDec)
        var keyObject ed25519.PrivKeyEd25519 = ed25519.PrivKeyEd25519{pp[0], pp[1], pp[2], pp[3], pp[4], pp[5], pp[6], pp[7], pp[8], pp[9], pp[10], pp[11], pp[12], pp[13], pp[14], pp[15], pp[16], pp[17], pp[18], pp[19], pp[20], pp[21], pp[22], pp[23], pp[24], pp[25], pp[26], pp[27], pp[28], pp[29], pp[30], pp[31], pp[32], pp[33], pp[34], pp[35], pp[36], pp[37], pp[38], pp[39], pp[40], pp[41], pp[42], pp[43], pp[44], pp[45], pp[46], pp[47], pp[48], pp[49], pp[50], pp[51], pp[52], pp[53], pp[54], pp[55], pp[56], pp[57], pp[58], pp[59], pp[60], pp[61], pp[62], pp[PrivKeyEd25519Size - 1]}

	pDec, _ := base64.StdEncoding.DecodeString(pub_key_b64)
        pk := []byte(pDec)
        var pubObject ed25519.PubKeyEd25519 = ed25519.PubKeyEd25519{pk[0], pk[1], pk[2], pk[3],pk[4], pk[5],pk[6], pk[7],pk[8], pk[9],pk[10], pk[11],pk[12], pk[13],pk[14], pk[15],pk[16], pk[17],pk[18], pk[19],pk[20], pk[21],pk[22], pk[23],pk[24], pk[25],pk[26], pk[27],pk[28], pk[29],pk[30], pk[PubKeyEd25519Size - 1]}

        return keyObject, pubObject
}
