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
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const (
	kmstool        = "kmstool_enclave_cli"
	vsockProxyPort = "8000" // vsock-proxy listen port, default 8000
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

	// encrypted private key from AWS Secrets Manager
	EncryptedEthKey string `json:"encryptedEthKey"`
}

func getSMEiphertext(ctx context.Context, secretRegion, secretARN string) (*Credential, error) {
	instanceCredsCache := aws.NewCredentialsCache(ec2rolecreds.New())
	instanceCreds, err := instanceCredsCache.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	// Create a new config with the credentials
	cfg := aws.NewConfig()
	cfg.Credentials = aws.NewCredentialsCache(
		credentials.NewStaticCredentialsProvider(
			instanceCreds.AccessKeyID,
			instanceCreds.SecretAccessKey,
			instanceCreds.SessionToken))
	cfg.Region = secretRegion

	// Create a Secrets Manager client
	conn := secretsmanager.NewFromConfig(*cfg)

	// Get the secret value
	result, err := conn.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &secretARN,
	})

	if err != nil {
		return nil, err
	}

	return &Credential{
		Region:          secretRegion,
		AccessKey:       instanceCreds.AccessKeyID,
		SecretAccessKey: instanceCreds.SecretAccessKey,
		SessionToken:    instanceCreds.SessionToken,
		EncryptedEthKey: *result.SecretString,
	}, err
}

func kmstoolEnclaveDecrypt(ctx context.Context, credential *Credential) (string, error) {
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
		return "", err
	}

	privkeyBytes, err := cmd.Output()
	if err != nil || len(privkeyBytes) == 0 {
		return "", err
	}

	var b64privkey string
	_, err = fmt.Sscanf(strings.TrimSpace(string(privkeyBytes)), "PLAINTEXT: %s\n", &b64privkey)
	if err != nil {
		return "", err
	}

	privkey, err := base64.StdEncoding.DecodeString(b64privkey)
	if err != nil {
		return "", err
	}

	return string(privkey), nil
}
