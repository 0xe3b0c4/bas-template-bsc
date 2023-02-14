package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/signer/core"
	"github.com/ethereum/go-ethereum/signer/fourbyte"
	"github.com/ethereum/go-ethereum/signer/storage"
)

func TestWalletSign(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	db, err := fourbyte.NewWithFile("")
	if err != nil {
		t.Fatalf("Failed to load 4byte db: %v", err)
	}

	keys := newMemKeyStore()
	am := accounts.NewManager(
		&accounts.Config{InsecureUnlockAllowed: true},
		keys,
	)

	api := core.NewSignerAPI(am, 20221, true, NewHeadlessConfirmUI(), db, false, &storage.NoStorage{})

	errs := make([]string, 0)
	addErr := func(errStr string) {
		log.Info("Test error", "err", errStr)
		errs = append(errs, errStr)
	}
	expectApprove := func(testcase string, err error) {
		if err == nil || err == accounts.ErrUnknownAccount {
			return
		}
		addErr(fmt.Sprintf("%v: expected no error, got %v", testcase, err.Error()))
	}

	{ // Sign data test
		Header := types.Header{
			ParentHash:  common.HexToHash("0000H45H"),
			UncleHash:   common.HexToHash("0000H45H"),
			Coinbase:    common.HexToAddress("0000H45H"),
			Root:        common.HexToHash("0000H00H"),
			TxHash:      common.HexToHash("0000H45H"),
			ReceiptHash: common.HexToHash("0000H45H"),
			Difficulty:  big.NewInt(1337),
			Number:      big.NewInt(1337),
			GasLimit:    1338,
			GasUsed:     1338,
			Time:        1338,
			Extra:       []byte("Extra data Extra data Extra data  Extra data  Extra data  Extra data  Extra data Extra data"),
			MixDigest:   common.HexToHash("0x0000H45H"),
		}
		headerRlp, err := rlp.EncodeToBytes(Header)
		if err != nil {
			utils.Fatalf("Should not error: %v", err)
		}
		addr, _ := common.NewMixedcaseAddressFromString("0x0011223344556677889900112233445566778899")
		_, err = api.SignData(ctx, accounts.MimetypeParlia, *addr, hexutil.Encode(headerRlp))
		expectApprove("signdata - header", err)
	}
	{ // Sign data test - typed data
		addr, _ := common.NewMixedcaseAddressFromString("0x0011223344556677889900112233445566778899")
		data := `{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"test","type":"uint8"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"Ether Mail","version":"1","chainId":"1","verifyingContract":"0xCCCcccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},"message":{"from":{"name":"Cow","test":"3","wallet":"0xcD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB","test":"2"},"contents":"Hello, Bob!"}}`
		//_, err := api.SignData(ctx, accounts.MimetypeTypedData, *addr, hexutil.Encode([]byte(data)))
		var typedData core.TypedData
		json.Unmarshal([]byte(data), &typedData)
		_, err := api.SignTypedData(ctx, *addr, typedData)
		expectApprove("sign 712 typed data", err)
	}
	{ // Sign data test - plain text
		api.UI.ShowInfo("Please approve the next request for signing text")
		addr, _ := common.NewMixedcaseAddressFromString("0x0011223344556677889900112233445566778899")
		_, err := api.SignData(ctx, accounts.MimetypeTextPlain, *addr, hexutil.Encode([]byte("hello world")))
		expectApprove("signdata - text", err)
	}
	{ // Sign transaction
		a := common.HexToAddress("0xdeadbeef000000000000000000000000deadbeef")
		api.UI.ShowInfo("Please reject next transaction")
		data := hexutil.Bytes([]byte{})
		to := common.NewMixedcaseAddress(a)
		tx := core.SendTxArgs{
			Data:     &data,
			Nonce:    0x1,
			Value:    hexutil.Big(*big.NewInt(6)),
			From:     common.NewMixedcaseAddress(a),
			To:       &to,
			GasPrice: hexutil.Big(*big.NewInt(5)),
			Gas:      1000,
			Input:    nil,
		}
		_, err := api.SignTransaction(ctx, tx, nil)
		expectApprove("sign transaction", err)
	}

	for _, e := range errs {
		t.Fatalf("Test failed: %v", e)
	}
}
