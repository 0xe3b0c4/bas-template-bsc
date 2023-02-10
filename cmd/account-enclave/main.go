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

// account-enclave is a utility that can be run external signer on a AWS Nitro Enclaves,
// private key use AWS Secrets Manager storage, decrypt and auth by AWS KMS
// It will listen for requests on a Linux vsock
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/signer/core"

	"gopkg.in/urfave/cli.v1"
)

const (
	enclaveExternalAPIVersion = "1.0.0"
	ReadTimeout               = 30 * time.Second
	WriteTimeout              = 30 * time.Second
	IdleTimeout               = 30 * time.Second
)

var (
	// Git information set by linker when building with ci.go.
	gitCommit string
	gitDate   string

	app = flags.NewApp(gitCommit, gitDate, "the external signer service")

	/// Flags definition
	// global flags
	chainID = cli.Int64Flag{
		Name:   "chainID",
		Usage:  "Chain ID for the signer",
		EnvVar: "CHAIN_ID",
		Hidden: true,
		Value:  0,
	}

	// vsock port
	vsockProt = cli.UintFlag{
		Name:   "vsock.prot",
		Usage:  "The vscok port on the enclave",
		EnvVar: "VSOCK_PROT",
		Hidden: true,
		Value:  8545,
	}

	// unseal command flags
	daemonFlag = cli.BoolFlag{
		Name:  "daemon",
		Usage: "Run as a daemon, if enclave restart try unseal account again",
	}

	regionFlag = cli.StringFlag{
		Name:  "aws.sm.region",
		Usage: "AWS Secrets Manager Region",
	}

	arnFlag = cli.StringFlag{
		Name:  "aws.sm.arn",
		Usage: "AWS Secrets Manager Secret ARN",
	}

	vsockUlr = cli.StringFlag{
		Name:  "vsock",
		Value: "vsock://16:8545",
		Usage: "The vscok endpoint (format \"vsock://<cid>:<port>\")",
	}

	// command
	UnsealCommand = cli.Command{
		Action:    unsealAccount,
		Name:      "unseal",
		Usage:     "unseal the private key in the enclave",
		ArgsUsage: "",
		Flags: []cli.Flag{
			daemonFlag,
			regionFlag,
			arnFlag,
			vsockUlr,
		},
		Description: `
This unseal command authenticates the IAM role of the EC2 instance with AWS KMS,
retrieves the encrypted private key from AWS Secrets Manager, 
and sends it to the enclave to unseal the private key so that the node can use it.`,
	}
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

var (
	appContext context.Context
	cancelFn   context.CancelFunc
)

func init() {
	// Initialize the CLI app and start action
	app.Name = "account-enclave"
	app.Action = enclaveAPIServer
	app.HideVersion = true
	app.Commands = []cli.Command{
		UnsealCommand,
	}
	app.Flags = append(app.Flags, chainID, vsockProt)
	cli.CommandHelpTemplate = flags.OriginCommandHelpTemplate
}

func main() {
	// init app context
	appContext, cancelFn = context.WithCancel(context.Background())
	defer cancelFn()

	if err := app.Run(os.Args); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func unsealAccount(ctx *cli.Context) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs

		cancelFn()
	}()

	isDaemon := ctx.Bool(daemonFlag.Name)
	region := ctx.String(regionFlag.Name)
	arn := ctx.String(arnFlag.Name)
	vsock := ctx.String(vsockUlr.Name)

	if !isDaemon {
		return sendUnsealRequest(vsock, region, arn)
	} else {
		for {
			select {
			case <-appContext.Done():
				return nil
			default:
			}

			err := sendUnsealRequest(vsock, region, arn)
			if err != nil {
				log.Error("daemon unseal account failed", "err", err)
			}
		}
	}
}

func enclaveAPIServer(ctx *cli.Context) error {
	chainID := ctx.Int64(chainID.Name)
	vsock := ctx.Uint(vsockProt.Name)

	signer := &enclaveSigner{}
	signer.init(chainID)

	listen, err := rpc.VsockListen(uint32(vsock))
	if err != nil {
		utils.Fatalf("Could not listen on vsock: %w", err)
	}

	var (
		auth EnclaveAuthentication
		api  EnclaveAPI
	)

	auth = signer
	api = signer.API()

	rpcAPI := []rpc.API{
		{
			Namespace: "enclave",
			Public:    true,
			Service:   auth,
			Version:   "1.0",
		},
		{
			Namespace: "account",
			Public:    true,
			Service:   api,
			Version:   "1.0",
		},
	}

	srv := rpc.NewServer()
	err = node.RegisterApisFromWhitelist(rpcAPI, []string{"account", "enclave"}, srv, false)
	if err != nil {
		utils.Fatalf("Could not register API: %w", err)
	}

	httpSrv := &http.Server{
		Handler:      srv,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		httpSrv.Shutdown(appContext)
	}()

	return httpSrv.Serve(listen)
}
