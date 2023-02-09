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
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/internal/flags"
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

	// modify this
	chainID   int64  = 0
	vsockProt uint32 = 8545
)

var (
	// Git information set by linker when building with ci.go.
	gitCommit string
	gitDate   string

	app = flags.NewApp(gitCommit, gitDate, "the external signer service")

	// flags
	daemonFlag = cli.BoolFlag{
		Name:  "daemon",
		Usage: "Run as a daemon, if enclave restart try unseal account again",
	}

	regionFlag = cli.StringFlag{
		Name:  "aws.sm.region",
		Usage: "AWS region",
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

type Credential struct {
	// AWS EC2 instance region
	Region string `json:"region"`

	// AWS EC2 instance iam account access key
	AccessKey string `json:"accessKey"`

	// AWS EC2 instance iam account  secret access key
	SecretAccessKey string `json:"secretAccessKey"`

	// AWS EC2 instance session token
	SessionToken string `json:"sessionToken"`

	// ChainID
	ChainID string `json:"chainID"`

	// encrypted private key from AWS Secrets Manager
	EncryptedEthKey string `json:"encryptedEthKey"`
}

// unlock private key from AWS Secrets Manager
type EnclaveAuthentication interface {
	// unseal private key
	Unseal(ctx context.Context, credential Credential) error
	// unseal status
	UnsealStatus(ctx context.Context) string
}

func init() {
	// Initialize
	app.Name = "account-enclave"
	app.Action = enclaveAPI
	app.HideVersion = true
	app.Commands = []cli.Command{
		UnsealCommand,
	}
	cli.CommandHelpTemplate = flags.OriginCommandHelpTemplate
}

func main() {
	if err := app.Run(os.Args); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func unsealAccount(ctx *cli.Context) error {
	// TODO
	return nil
}

func enclaveAPI(ctx *cli.Context) error {
	signer := &enclaveSigner{}
	signer.init()

	listen, err := rpc.VsockListen(vsockProt)
	if err != nil {
		utils.Fatalf("Could not listen on vsock: %w", err)
	}

	var (
		auth EnclaveAuthentication
		api  core.ExternalAPI
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

	httpSrv.Serve(listen)

	return nil
}
