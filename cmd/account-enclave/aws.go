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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
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
