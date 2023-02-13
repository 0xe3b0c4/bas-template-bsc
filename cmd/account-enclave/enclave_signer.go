// Copyright 2023 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/signer/core"
	"github.com/ethereum/go-ethereum/signer/fourbyte"
	"github.com/ethereum/go-ethereum/signer/storage"
)

var (
	// ErrLocked is returned when the account is locked.
	ErrAccountNotUnseal = fmt.Errorf("account not unseal")

	// SealState
	SealState = "seal"

	// UnsealState
	UnsealState = "unseal"

	// UnsealMessage
	UnsealMessageFailed  = "unseal_failed"
	UnsealMessageSuccess = "unseal_success"
)

// wrapper for the external API, but remove the `New` method
type EnclaveAPI interface {
	// List available accounts
	List(ctx context.Context) ([]common.Address, error)
	// SignTransaction request to sign the specified transaction
	SignTransaction(ctx context.Context, args core.SendTxArgs, methodSelector *string) (*ethapi.SignTransactionResult, error)
	// SignData - request to sign the given data (plus prefix)
	SignData(ctx context.Context, contentType string, addr common.MixedcaseAddress, data interface{}) (hexutil.Bytes, error)
	// SignTypedData - request to sign the given structured data (plus prefix)
	SignTypedData(ctx context.Context, addr common.MixedcaseAddress, data core.TypedData) (hexutil.Bytes, error)
	// EcRecover - recover public key from given message and signature
	EcRecover(ctx context.Context, data hexutil.Bytes, sig hexutil.Bytes) (common.Address, error)
	// Version info about the APIs
	Version(ctx context.Context) (string, error)
	// SignGnosisSafeTransaction signs/confirms a gnosis-safe multisig transaction
	SignGnosisSafeTx(ctx context.Context, signerAddress common.MixedcaseAddress, gnosisTx core.GnosisSafeTx, methodSelector *string) (*core.GnosisSafeTx, error)
}

// unlock private key from AWS Secrets Manager
type EnclaveAuthentication interface {
	// unseal private key
	Unseal(ctx context.Context, credential Credential) (string, error)
	// unseal status
	Status(ctx context.Context) string
}

type enclaveSigner struct {
	unsealMux sync.Mutex

	api  *core.SignerAPI
	keys *memKeyStore
}

func (signer *enclaveSigner) init(chainID int64) {
	db, err := fourbyte.NewWithFile("")
	if err != nil {
		panic(err)
	}

	embeds, locals := db.Size()
	log.Info("Loaded 4byte database", "embeds", embeds, "locals", locals)

	signer.keys = newMemKeyStore()
	am := accounts.NewManager(
		&accounts.Config{InsecureUnlockAllowed: true},
		signer.keys,
	)

	signer.api = core.NewSignerAPI(am, chainID, true, NewHeadlessConfirmUI(), db, false, &storage.NoStorage{})
}

func (signer *enclaveSigner) API() *core.SignerAPI {
	return signer.api
}

// unseal private key
// call kmstool_enclave_cli tool to get private key from AWS Secrets Manager
func (signer *enclaveSigner) Unseal(ctx context.Context, credential Credential) (string, error) {
	signer.unsealMux.Lock()

	// unlock after 5 seconds, aws api limit call rate
	defer func() {
		go func() {
			time.Sleep(5 * time.Second)
			signer.unsealMux.Unlock()
		}()
	}()

	privkey, err := kmstoolEnclaveDecrypt(ctx, &credential)
	if err != nil {
		return UnsealMessageFailed, err
	}

	key, err := crypto.HexToECDSA(string(privkey))
	if err != nil {
		return UnsealMessageFailed, err
	}

	_, err = signer.keys.ImportECDSA(key)
	if err != nil {
		return UnsealMessageFailed, err
	}

	return UnsealMessageSuccess, err
}

func (signer *enclaveSigner) Status(ctx context.Context) string {
	if len(signer.keys.Wallets()) > 0 {
		return UnsealState
	}

	return SealState
}

// sendUnsealRequest send unseal request to enclave
func sendUnsealRequest(vsock, region, arn string) error {
	timeoutCtx, cancel := context.WithTimeout(appContext, time.Minute)
	defer cancel()

	client, err := rpc.DialContext(timeoutCtx, vsock)
	if err != nil {
		return err
	}
	defer client.Close()

	var stateResult string
	if err := client.CallContext(timeoutCtx, &stateResult, "enclave_state"); err != nil {
		return err
	}

	// if enclave is unseal, skip it
	if stateResult == SealState {
		return nil
	}

	credential, err := getSMEiphertext(timeoutCtx, region, arn)
	if err != nil {
		return err
	}

	var unsealResult string
	if err := client.CallContext(timeoutCtx, &unsealResult, "enclave_Unseal", credential); err != nil {
		return err
	}

	log.Info("enclave unseal result", "status", unsealResult)

	return nil
}
