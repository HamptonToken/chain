/*
test big number for wallet to use.
only test usages used for the wallet.
*/
package main

import (
    "fmt"
    "math/big"
)

func main() {
	/*
	  func (z *Int) SetString(s string, base int) (*Int, bool)
            SetString sets z to the value of s, interpreted in the given base, and returns z and 
	    a boolean indicating success. The entire string (not just a prefix) must be valid for success. 
	    If SetString fails, the value of z is undefined but the returned value is nil.
	*/
	big1, err := new(big.Int).SetString("99999999999999999999999900000000111122223333", 10)
	if !err {
		fmt.Println("error", err, big1)
	}

	big2, err := new(big.Int).SetString("98999999999999999999999900000000111122223333", 10)
	if !err {
		fmt.Println("error2", err, big2)
	}

	// subtract
	fmt.Println(new(big.Int).Sub(big1, big2))

	// subtract 1, method 1
	big3, _ := new(big.Int).SetString("1", 10)
	fmt.Println(new(big.Int).Sub(big1, big3))
	// subtract 1, method 2
	fmt.Println(new(big.Int).Sub(big1, new(big.Int).SetInt64(1)))
	// subtract 1, method 3
	fmt.Println(new(big.Int).Sub(big1, new(big.Int).SetUint64(1)))

	//add
	fmt.Println(new(big.Int).Add(big1, big2))

	// small number sub big number, get negative number
	fmt.Println(new(big.Int).Sub(big2, big1))

	// test toString()
	var str string = ""
	str = big1.String()
	fmt.Println(str)

	// test comparison
	// retrun -1 if x <  y
        // return 0 if x == y
        // return 1 if x >  y
	fmt.Println(big1.Cmp(big2))
	
	zeroN, _ := new(big.Int).SetString("0", 10)
	negN, _ := new(big.Int).SetString("-1111111111111111", 10)

	fmt.Println(big1.Cmp(zeroN)) // more than 0, so return 1
	fmt.Println(negN.Cmp(zeroN)) // less than 0, so return -1

	// test invalid number
	_, err = new(big.Int).SetString("99999999999999999999999900000000111122223333a", 10)
	if !err {
		fmt.Println("invalid number, ", err)
	}
}
