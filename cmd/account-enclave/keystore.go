package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
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
)

const (
	kmstool        = "kmstool_enclave_cli"
	vsockProxyPort = "8000" // vsock-proxy listen port, default 8000
)

func randomString(strlen int) string {
	b := make([]byte, strlen)
	rand.Read(b)
	return string(b)
}

type enclaveSigner struct {
	am   *accounts.Manager
	api  *core.SignerAPI
	keys *keystore.KeyStore
}

func (signer *enclaveSigner) init() {
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
func (signer *enclaveSigner) Unseal(ctx context.Context, credential Credential) error {
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
		return err
	}

	b64privkey, err := cmd.Output()
	if err != nil {
		return err
	}

	privkey, err := base64.StdEncoding.DecodeString(string(b64privkey))
	if err != nil {
		return err
	}

	key, err := crypto.HexToECDSA(string(privkey))
	if err != nil {
		return err
	}

	// generate disposable password
	password := randomString(32)
	account := accounts.Account{Address: crypto.PubkeyToAddress(key.PublicKey)}

	account, err = signer.keys.ImportECDSA(key, password)
	if err != nil {
		return err
	}

	err = signer.keys.Unlock(account, password)
	if err != nil {
		return err
	}

	// cache the account
	_, err = signer.am.Find(account)
	if err != nil {
		return err
	}

	return nil
}

func (signer *enclaveSigner) UnsealStatus(ctx context.Context) string {
	return "seal"
}
