package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
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

const (
	kmstool        = "kmstool_enclave_cli"
	vsockProxyPort = "8000" // vsock-proxy listen port, default 8000
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

	am   *accounts.Manager
	api  *core.SignerAPI
	keys *keystore.KeyStore
}

func (signer *enclaveSigner) init(chainID int64) {
	db, err := fourbyte.NewWithFile("")
	if err != nil {
		panic(err)
	}

	embeds, locals := db.Size()
	log.Info("Loaded 4byte database", "embeds", embeds, "locals", locals)

	signer.keys = keystore.NewKeyStore(
		os.TempDir(),
		keystore.StandardScryptN,
		keystore.StandardScryptP,
	)

	am := accounts.NewManager(
		&accounts.Config{InsecureUnlockAllowed: false},
		signer.keys,
	)

	signer.api = core.NewSignerAPI(am, chainID, true, nil, db, false, &storage.NoStorage{})
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

	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(
		timeoutCtx,
		kmstool,
		"--region", credential.Region,
		"--proxy-port", vsockProxyPort,
		"--aws-access-key-id", credential.AccessKey,
		"--aws-secret-access-key", credential.SecretAccessKey,
		"--aws-session-token", credential.SessionToken,
		"--ciphertext", credential.EncryptedEthKey,
	)

	err := cmd.Wait()
	if err != nil {
		return UnsealMessageFailed, err
	}

	privkeyBytes, err := cmd.Output()
	if err != nil || len(privkeyBytes) == 0 {
		return UnsealMessageFailed, err
	}

	b64privkey := strings.TrimSpace(string(privkeyBytes))

	privkey, err := base64.StdEncoding.DecodeString(string(b64privkey))
	if err != nil {
		return UnsealMessageFailed, err
	}

	key, err := crypto.HexToECDSA(string(privkey))
	if err != nil {
		return UnsealMessageFailed, err
	}

	// generate tmp keystore password
	// aws enclaves can't access the /dev/random or /dev/urandom device
	privHash := sha512.Sum512(privkey)
	password := hex.EncodeToString(privHash[:16])
	account := accounts.Account{Address: crypto.PubkeyToAddress(key.PublicKey)}

	account, err = signer.keys.ImportECDSA(key, password)
	if err != nil {
		return UnsealMessageFailed, err
	}

	err = signer.keys.Unlock(account, password)
	if err != nil {
		return UnsealMessageFailed, err
	}

	// cache the account
	_, err = signer.am.Find(account)
	if err != nil {
		return UnsealMessageFailed, err
	}

	return UnsealMessageSuccess, err
}

func (signer *enclaveSigner) Status(ctx context.Context) string {
	if len(signer.keys.Accounts()) > 0 {
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
