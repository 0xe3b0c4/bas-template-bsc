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
	"sync"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
)

type memKeyStore struct {
	mux     sync.RWMutex
	wallets map[common.Address]*memWallet
}

func newMemKeyStore() *memKeyStore {
	return &memKeyStore{
		wallets: make(map[common.Address]*memWallet),
	}
}

func (store *memKeyStore) ImportECDSA(key *ecdsa.PrivateKey) (accounts.Wallet, error) {
	store.mux.Lock()
	defer store.mux.Unlock()

	wallet := &memWallet{
		Address:    crypto.PubkeyToAddress(key.PublicKey),
		PrivateKey: key,
	}

	store.wallets[wallet.Address] = wallet

	return wallet, nil
}

func (store *memKeyStore) Wallets() []accounts.Wallet {
	store.mux.RLock()
	defer store.mux.RUnlock()

	var wallets []accounts.Wallet
	for _, wallet := range store.wallets {
		wallets = append(wallets, wallet)
	}

	return wallets
}

// Subscribe is a noop for the in-memory keystore.
func (store *memKeyStore) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	return event.NewSubscription(func(quit <-chan struct{}) error {
		<-quit
		return nil
	})
}
