package main

import (
	"fmt"
	"time"
	"math/rand"
	_ "encoding/hex"
	_ "encoding/json"

	"github.com/tendermint/tendermint/rpc/client"
	"github.com/tendermint/tendermint/types"
	cmn "github.com/tendermint/tendermint/libs/common"
)

const coin_address1 = "B508ED0D54597D516A680E7951F18CAD24C7EC9F"
const coin_address2 = "2234567890123456789012345678901234567890"

func getHTTPClient(ip, port string) *client.HTTP {
	return client.NewHTTP(ip + ":" + port, "/websocket")
}

var nonce int = 0

func main()  {
	cl := getHTTPClient("127.0.0.1", "26657")
	status, err := cl.Status()
	if err == nil {
		fmt.Println("LatestBlockHeight:", status.SyncInfo.LatestBlockHeight)
        }

	src := rand.NewSource(time.Now().UnixNano())
        rr := rand.New(src)
        nonce = rr.Intn(10000)

	fmt.Println("Transfer 150 coins from address1 to address2")
	fmt.Println("Before transaction, show balance of two accounts.")

	// case 1
	// now we can check the balance of address1 and address2
	// curl  'localhost:26657/abci_query?data="bal:1234567890123456789012345678901234567890:1"'
	res, err := cl.ABCIQuery("/websocket", cmn.HexBytes(fmt.Sprintf("%s:%s", "bal", coin_address1)))
	qres := res.Response
	fmt.Println("query status:", qres.IsOK())
	fmt.Println("address1 balance:", string(qres.Value))

	res, err = cl.ABCIQuery("/websocket", cmn.HexBytes(fmt.Sprintf("%s:%s", "bal", coin_address2)))
	qres = res.Response
	fmt.Println("query status:", qres.IsOK())
	fmt.Println("address2 balance:", string(qres.Value))

        // case 2
	// send 600 coins from address1 to address2.
        // curl -s 'localhost:26657/broadcast_tx_commit?tx="trx_send=B508ED0D54597D516A680E7951F18CAD24C7EC9F:1234567890123456789012345678901234567890:600"' 
	// the first address coin was pre-allocated. so don't worry if it has enough fund.
	nonce++
	fmt.Println("nonce:", nonce)
	btr, err := cl.BroadcastTxCommit(types.Tx(
		fmt.Sprintf("%s=%s:%s:%s:%s", string("trx_send"), coin_address1, coin_address2, "150", fmt.Sprintf("%d", nonce))))

	if err != nil {
            fmt.Println(err)
	    return
	}

	fmt.Println("Current height:", btr.Height)
	client.WaitForHeight(cl, btr.Height + 1, nil)

	// case 3
	// again, we can check the balance of address1
	// curl  'localhost:26657/abci_query?data="bal:1234567890123456789012345678901234567890"'
	fmt.Println("After transaction, show balance of two accounts:")
	res, err = cl.ABCIQuery("/websocket", cmn.HexBytes(fmt.Sprintf("%s:%s", "bal", coin_address1)))
	qres = res.Response
	fmt.Println("query status:", qres.IsOK())
	fmt.Println("address1 balance:", string(qres.Value))

	res, err = cl.ABCIQuery("/websocket", cmn.HexBytes(fmt.Sprintf("%s:%s", "bal", coin_address2)))
	qres = res.Response
	fmt.Println("query status:", qres.IsOK())
	fmt.Println("address2 balance:", string(qres.Value))
}
