package tester

import (
    . "github.com/smartystreets/goconvey/convey"
    "testing"
)

var  key = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAHFNZ8+2UnV72fsnUciUAoHYiBKY+FO7IZoT2TPMUUaoAoGCCqGSM49
AwEHoUQDQgAEM49mdr428vS5+uHc0wjJBqyQ5n8d0QLra97C40uaEw94l6RWjMOG
bQfHGg6YbZzQ6Zc0qIxf7xu+RX//sTmqCQ==
-----END EC PRIVATE KEY-----`

func TestGenerateKeys(t *testing.T) {
    Convey("generate key", t, func() {
        priv, pub, addr := wallet.GenerateKeys()
        address, err := wallet.GetAddressByPublicKey(pub)
        So(addr, ShouldEqual, address)
        _, err = wallet.Sign("123456", priv)
        So(err, ShouldBeNil)
        //if err == nil {
        //    err = wallet.SetValidator("127.0.0.1", "26657", pub, "1")
        //    if err != nil {
        //        t.Error("setValidator error")
        //    }
        //} else {
        //    t.Error("do sha256 sign, failure.")
        //}
    })
}

func TestSetBalance(t *testing.T) {
    priv, _, addr := wallet.GenerateKeys()
    Convey("Test Set Balance", t, func() {
        Convey("set balance in address", func() {
            wallet.SetBalance("127.0.0.1", "26657",addr, "10", priv)
            balance, err := wallet.GetBalance("127.0.0.1", "26657", addr)
            if err != nil {
                t.Error("get balance error", err)
            }
            So(balance, ShouldEqual, "10")
        })
    })
}

func TestSendCoin(t *testing.T) {
    Convey("Test SendCoin", t, func() {
        priv, pub, addr := wallet.GenerateKeys()
        _, _, addrT := wallet.GenerateKeys()
        wallet.SetBalance("127.0.0.1", "26657", addr, "10", priv)
        _,err := wallet.SendCoins("127.0.0.1", "26657", priv, addr, addrT, "1", pub)
        if err != nil {
            t.Error("wallet send coins error")
        }
        balance2, err := wallet.GetBalance("127.0.0.1", "26657", addr)
        if err != nil {
            t.Error("get balance error", err)
        }
        balanceT, err := wallet.GetBalance("127.0.0.1", "26657", addrT)
        if err != nil {
            t.Error("get balance error", err)
        }
        So(balance2, ShouldEqual, "9")
        So(balanceT, ShouldEqual, "1")

    })
}


func TestMetering(t *testing.T) {
  key := `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAHFNZ8+2UnV72fsnUciUAoHYiBKY+FO7IZoT2TPMUUaoAoGCCqGSM49
AwEHoUQDQgAEM49mdr428vS5+uHc0wjJBqyQ5n8d0QLra97C40uaEw94l6RWjMOG
bQfHGg6YbZzQ6Zc0qIxf7xu+RX//sTmqCQ==
-----END EC PRIVATE KEY-----`
  Convey("Test merter", t, func() {
      err := wallet.SetMetering("127.0.0.1", "26657",
          key,   // priv_key
          "dc1", // data center
          "ns1", // name space
          "value")

      So(err, ShouldBeNil)
  })
}

func TestGetMeter(t *testing.T) {
  Convey("test get meter",t, func() {
      _, err := wallet.GetHistoryMetering("127.0.0.1", "26657", "datacenter_name", "test-deploy", false, 0, 0)
      So(err, ShouldBeNil)
  })
}
