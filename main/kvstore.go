package hmetachain

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"math/big"

	"github.com/tendermint/tendermint/abci/example/code"
	"github.com/tendermint/tendermint/abci/types"
	cmn "github.com/tendermint/tendermint/libs/common"
	dbm "github.com/tendermint/tendermint/libs/db"
	"github.com/tendermint/tendermint/version"
)

var (
	stateKey        = []byte("stateKey")
	kvPairPrefixKey = []byte("kvPairKey:")

	ProtocolVersion version.Protocol = 0x1
)

type State struct {
	db      dbm.DB
	Size    int64  `json:"size"`
	Height  int64  `json:"height"`
	AppHash []byte `json:"app_hash"`
}

func loadState(db dbm.DB) State {
	stateBytes := db.Get(stateKey)
	var state State
	if len(stateBytes) != 0 {
		err := json.Unmarshal(stateBytes, &state)
		if err != nil {
			panic(err)
		}
	}
	state.db = db
	return state
}

func saveState(state State) {
	stateBytes, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	state.db.Set(stateKey, stateBytes)
}

func prefixKey(key []byte) []byte {
	return append(kvPairPrefixKey, key...)
}

//---------------------------------------------------

var _ types.Application = (*KVStoreApplication)(nil)

type KVStoreApplication struct {
	types.BaseApplication

	state State
}

func NewKVStoreApplication() *KVStoreApplication {
	state := loadState(dbm.NewMemDB())
	return &KVStoreApplication{state: state}
}

func (app *KVStoreApplication) Info(req types.RequestInfo) (resInfo types.ResponseInfo) {
	return types.ResponseInfo{
		Data:       fmt.Sprintf("{\"size\":%v}", app.state.Size),
		Version:    version.ABCIVersion,
		AppVersion: ProtocolVersion.Uint64(),
	}
}

// tx is either "key=value" or just arbitrary bytes
func (app *KVStoreApplication) DeliverTx(tx []byte) types.ResponseDeliverTx {
	var key, value []byte
	parts := bytes.Split(tx, []byte("="))
	if len(parts) == 2 {
		key, value = parts[0], parts[1]
	} else {
		key, value = tx, tx
	}
	app.state.db.Set(prefixKey(key), value)
	app.state.Size += 1

	tags := []cmn.KVPair{
		{Key: []byte("app.creator"), Value: []byte("Cosmoshi Netowoko")},
		{Key: []byte("app.key"), Value: key},
	}
	return types.ResponseDeliverTx{Code: code.CodeTypeOK, Tags: tags}
}

func (app *KVStoreApplication) CheckTx(tx []byte) types.ResponseCheckTx {
	return types.ResponseCheckTx{Code: code.CodeTypeOK, GasWanted: 1}
}

func (app *KVStoreApplication) Commit() types.ResponseCommit {
	// Using a memdb - just return the big endian size of the db
	appHash := make([]byte, 8)
	binary.PutVarint(appHash, app.state.Size)
	app.state.AppHash = appHash
	app.state.Height += 1
	saveState(app.state)
	return types.ResponseCommit{Data: appHash}
}

func (app *KVStoreApplication) Query(reqQuery types.RequestQuery) (resQuery types.ResponseQuery) {
	isBalance := false

	if reqQuery.Prove {
		value := app.state.db.Get(prefixKey(reqQuery.Data))
		resQuery.Index = -1 // TODO make Proof return index
		resQuery.Key = reqQuery.Data
		resQuery.Value = value
		if value != nil {
			resQuery.Log = "exists"
		} else {
			resQuery.Log = "does not exist"
		}
		return
	} else {
		resQuery.Key = reqQuery.Data
		value := []byte("")
		if string(reqQuery.Data[:3]) == AccountBlancePrefix[:3] {
		    isBalance = true
		    value = app.state.db.Get(reqQuery.Data)
		} else if len(reqQuery.Data) >= 3 && string(reqQuery.Data[:3]) == AccountStakePrefix[:3]{
		    value = app.state.db.Get(reqQuery.Data)
		} else if len(reqQuery.Data) >= 3 && string(reqQuery.Data[:3]) == MeteringPrefix[:3]{
		    value = app.state.db.Get(reqQuery.Data)
		} else if len(reqQuery.Data) >= 3 && string(reqQuery.Data[:3]) == CertPrefix[:3]{
		    value = app.state.db.Get(reqQuery.Data)
		} else if len(reqQuery.Data) >= 13 && string(reqQuery.Data[:13]) == SET_CRT_NONCE{
		    value = app.state.db.Get(reqQuery.Data)
		} else if len(reqQuery.Data) >= 11 && string(reqQuery.Data[:11]) == SET_OP_NONCE{
		    value = app.state.db.Get(reqQuery.Data)
		} else if len(reqQuery.Data) >= 9 && string(reqQuery.Data[:9]) == SET_VAL_NONCE{
		    value = app.state.db.Get(reqQuery.Data)
		} else if len(reqQuery.Data) >= 13 && string(reqQuery.Data[:13]) == RMV_CRT_NONCE{
		    value = app.state.db.Get(reqQuery.Data)
		} else if len(reqQuery.Data) >= 19 && string(reqQuery.Data[:19]) == ADMIN_OP_VAL_PUBKEY_NAME{
		    value = app.state.db.Get(reqQuery.Data)
		} else if len(reqQuery.Data) >= 20 && string(reqQuery.Data[:20]) == ADMIN_OP_FUND_PUBKEY_NAME{
		    value = app.state.db.Get(reqQuery.Data)
		} else if len(reqQuery.Data) >= 24 && string(reqQuery.Data[:24]) == ADMIN_OP_METERING_PUBKEY_NAME{
		    value = app.state.db.Get(reqQuery.Data)
		} else if len(reqQuery.Data) >= len(AllAccountsPrefix) &&
					string(reqQuery.Data[:len(AllAccountsPrefix)]) == AllAccountsPrefix {
                    itr := app.state.db.Iterator(nil, nil)
                    for ; itr.Valid(); itr.Next() {
			if len(itr.Key()) >= len(AccountBlancePrefix) &&
					string(itr.Key()[0:len(AccountBlancePrefix)]) == AccountBlancePrefix {
			    valueItem := []byte("")
			    valueItem = app.state.db.Get(itr.Key())
			    if len(valueItem) != 0 {
				    value = []byte(string(value) + string(itr.Key()[len(AccountBlancePrefix):]) + ":" + string(valueItem) + ";")
		            }
                        }
                    }
		} else if len(reqQuery.Data) >= len(AllCrtsPrefix) && string(reqQuery.Data[:len(AllCrtsPrefix)]) == AllCrtsPrefix {
                    itr := app.state.db.Iterator(nil, nil)
                    for ; itr.Valid(); itr.Next() {
			if len(itr.Key()) >= len(CertPrefix) && string(itr.Key()[0:len(CertPrefix)]) == CertPrefix {
			    valueItem := []byte("")
			    valueItem = app.state.db.Get(itr.Key())
			    if len(valueItem) != 0 {
				    value = []byte(string(value) + string(itr.Key()[len(CertPrefix):]) + ";")
		            }
                        }
                    }
		} else {
		    value = app.state.db.Get(prefixKey(reqQuery.Data))
		}

		//fmt.Println("queried value:", value)
		resQuery.Value = value

		if value != nil {
			if isBalance {
			    trxGetBalanceSlices := strings.Split(string(value), ":")
			    if len(trxGetBalanceSlices) == 1 {
				    _, err := new(big.Int).SetString(string(value), 10)
				    if !err {
					    resQuery.Log = "internal error, value format incorrect, single value"
					    return
				    }
			    } else if len(trxGetBalanceSlices) == 2 {
				    _, berr := new(big.Int).SetString(trxGetBalanceSlices[0], 10)
				    if !berr {
					    resQuery.Log = "internal error, value format incorrect, first value"
					    return
				    }

				    _, err := strconv.ParseInt(string(trxGetBalanceSlices[1]), 10, 64)
				    if err != nil {
					    resQuery.Log = "internal error, value format incorrect, second value"
					    return
				    }

			    } else {
				    resQuery.Log = "internal error, value format incorrect, extra value"
				    return
			    }
		        }

		        resQuery.Log = "exists"
		} else {
			resQuery.Log = "does not exist"
		}
		return
	}
}
