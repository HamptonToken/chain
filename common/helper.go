package common

import (
        "fmt"

        "github.com/tendermint/tendermint/abci/types"
)
/* public key in %X, base 16 with upper-case letters for A-F*/
func MakeValSetChangeTx(pubkey types.PubKey, power int64) []byte {
        return []byte(fmt.Sprintf("val:%X/%d", pubkey.Data, power))
}
