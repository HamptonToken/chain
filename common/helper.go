package common

import (
        "fmt"

        "github.com/tendermint/tendermint/abci/types"
)

func MakeValSetChangeTx(pubkey types.PubKey, power int64) []byte {
        return []byte(fmt.Sprintf("val:%X/%d", pubkey.Data, power))
}
