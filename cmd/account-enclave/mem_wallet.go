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
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	WalletStatusUnlocked = "unlocked"
)

var (
	ErrNoSupported = fmt.Errorf("operation not supported on enclave signers")
)

// Wallet implements accounts.Wallet, copy from accounts/keystore/keystore.go
type memWallet struct {
	// to simplify lookups we also store the address
	Address common.Address
	// we only store privkey as pubkey/address can be derived from it
	// privkey in this struct is always in plaintext
	PrivateKey *ecdsa.PrivateKey
}

// Accounts implements accounts.Wallet, only return one account
func (w *memWallet) Accounts() []accounts.Account {
	return []accounts.Account{{
		Address: w.Address,
	}}
}

// Contains implements accounts.Wallet, check if the wallet account equals the
func (w *memWallet) Contains(account accounts.Account) bool {
	return account.Address == w.Address
}

// URL implements accounts.Wallet, return const url
func (w *memWallet) URL() accounts.URL {
	return accounts.URL{
		Scheme: "enclave",
		Path:   w.Address.Hex(),
	}
}

// Status implements accounts.Wallet, always return unlocked
func (w *memWallet) Status() (string, error) {
	return WalletStatusUnlocked, nil
}

/// Not implemented

func (w *memWallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	return accounts.Account{}, ErrNoSupported
}

func (w *memWallet) SelfDerive(bases []accounts.DerivationPath, chain ethereum.ChainStateReader) {
}

func (w *memWallet) Open(passphrase string) error {
	return ErrNoSupported
}

func (w *memWallet) Close() error {
	return ErrNoSupported
}

// signHash sign hash with private key
func (w *memWallet) signHash(account accounts.Account, hash []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}

	return crypto.Sign(hash, w.PrivateKey)
}

/// Implement copy from accounts/keystore/wallet.go
func (w *memWallet) SignData(account accounts.Account, mimeType string, data []byte) ([]byte, error) {
	return w.signHash(account, crypto.Keccak256(data))
}

func (w *memWallet) SignDataWithPassphrase(account accounts.Account, passphrase, mimeType string, data []byte) ([]byte, error) {
	return w.signHash(account, crypto.Keccak256(data))
}

func (w *memWallet) SignText(account accounts.Account, text []byte) ([]byte, error) {
	return w.signHash(account, accounts.TextHash(text))
}

func (w *memWallet) SignTextWithPassphrase(account accounts.Account, passphrase string, text []byte) ([]byte, error) {
	return w.signHash(account, accounts.TextHash(text))
}

// SignTx implements accounts.Wallet, sign tx with private key
// from accounts/keystore/keystore.go
func (w *memWallet) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}

	// Depending on the presence of the chain ID, sign with 2718 or homestead
	signer := types.LatestSignerForChainID(chainID)
	return types.SignTx(tx, signer, w.PrivateKey)
}

func (w *memWallet) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}

	signer := types.LatestSignerForChainID(chainID)
	return types.SignTx(tx, signer, w.PrivateKey)
}
