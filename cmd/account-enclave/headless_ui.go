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
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/signer/core"
)

type HeadlessConfirmUI struct {
	mu sync.Mutex
}

func NewHeadlessConfirmUI() *HeadlessConfirmUI {
	return &HeadlessConfirmUI{}
}

func (ui *HeadlessConfirmUI) RegisterUIServer(api *core.UIServerAPI) {
	// noop
}

func (ui *HeadlessConfirmUI) OnInputRequired(info core.UserInputRequest) (core.UserInputResponse, error) {
	return core.UserInputResponse{Text: info.Prompt}, nil
}

// sanitize quotes and truncates 'txt' if longer than 'limit'. If truncated,
// and ellipsis is added after the quoted string
func sanitize(txt string, limit int) string {
	if len(txt) > limit {
		return fmt.Sprintf("%q...", txt[:limit])
	}
	return fmt.Sprintf("%q", txt)
}

func showMetadata(metadata core.Metadata) {
	fmt.Printf("Request context:\n\t%v -> %v -> %v\n", metadata.Remote, metadata.Scheme, metadata.Local)
	fmt.Printf("\nAdditional HTTP header data, provided by the external caller:\n")
	fmt.Printf("\tUser-Agent: %v\n\tOrigin: %v\n", sanitize(metadata.UserAgent, 200), sanitize(metadata.Origin, 100))
}

// ApproveTx prompt the user for confirmation to request to sign Transaction
func (ui *HeadlessConfirmUI) ApproveTx(request *core.SignTxRequest) (core.SignTxResponse, error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	weival := request.Transaction.Value.ToInt()
	fmt.Printf("--------- Transaction request-------------\n")
	if to := request.Transaction.To; to != nil {
		fmt.Printf("to:    %v\n", to.Original())
		if !to.ValidChecksum() {
			fmt.Printf("\nWARNING: Invalid checksum on to-address!\n\n")
		}
	} else {
		fmt.Printf("to:    <contact creation>\n")
	}
	fmt.Printf("from:     %v\n", request.Transaction.From.String())
	fmt.Printf("value:    %v wei\n", weival)
	fmt.Printf("gas:      %v (%v)\n", request.Transaction.Gas, uint64(request.Transaction.Gas))
	fmt.Printf("gasprice: %v wei\n", request.Transaction.GasPrice.ToInt())
	fmt.Printf("nonce:    %v (%v)\n", request.Transaction.Nonce, uint64(request.Transaction.Nonce))
	if chainId := request.Transaction.ChainID; chainId != nil {
		fmt.Printf("chainid:  %v\n", chainId)
	}
	if list := request.Transaction.AccessList; list != nil {
		fmt.Printf("Accesslist\n")
		for i, el := range *list {
			fmt.Printf(" %d. %v\n", i, el.Address)
			for j, slot := range el.StorageKeys {
				fmt.Printf("   %d. %v\n", j, slot)
			}
		}
	}
	if request.Transaction.Data != nil {
		d := *request.Transaction.Data
		if len(d) > 0 {
			fmt.Printf("data:     %v\n", hexutil.Encode(d))
		}
	}
	if request.Callinfo != nil {
		fmt.Printf("\nTransaction validation:\n")
		for _, m := range request.Callinfo {
			fmt.Printf("  * %s : %s\n", m.Typ, m.Message)
		}
		fmt.Println()

	}
	fmt.Printf("\n")
	showMetadata(request.Meta)
	fmt.Printf("-------------------------------------------\n")
	return core.SignTxResponse{Transaction: request.Transaction, Approved: true}, nil
}

// ApproveSignData prompt the user for confirmation to request to sign data
func (ui *HeadlessConfirmUI) ApproveSignData(request *core.SignDataRequest) (core.SignDataResponse, error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	fmt.Printf("-------- Sign data request--------------\n")
	fmt.Printf("Account:  %s\n", request.Address.String())
	if len(request.Callinfo) != 0 {
		fmt.Printf("\nValidation messages:\n")
		for _, m := range request.Callinfo {
			fmt.Printf("  * %s : %s\n", m.Typ, m.Message)
		}
		fmt.Println()
	}
	fmt.Printf("messages:\n")
	for _, nvt := range request.Messages {
		fmt.Printf("\u00a0\u00a0%v\n", strings.TrimSpace(nvt.Pprint(1)))
	}
	fmt.Printf("raw data:  \n\t%q\n", request.Rawdata)
	fmt.Printf("data hash:  %v\n", request.Hash)
	fmt.Printf("-------------------------------------------\n")
	showMetadata(request.Meta)
	return core.SignDataResponse{Approved: true}, nil
}

// ApproveListing prompt the user for confirmation to list accounts
// the list of accounts to list can be modified by the UI
func (ui *HeadlessConfirmUI) ApproveListing(request *core.ListRequest) (core.ListResponse, error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	fmt.Printf("-------- List Account request--------------\n")
	fmt.Printf("A request has been made to list all accounts. \n")
	fmt.Printf("You can select which accounts the caller can see\n")
	for _, account := range request.Accounts {
		fmt.Printf("  [x] %v\n", account.Address.Hex())
		fmt.Printf("    URL: %v\n", account.URL)
	}
	fmt.Printf("-------------------------------------------\n")
	showMetadata(request.Meta)

	return core.ListResponse{Accounts: request.Accounts}, nil
}

// ApproveNewAccount prompt the user for confirmation to create new Account, and reveal to caller
func (ui *HeadlessConfirmUI) ApproveNewAccount(request *core.NewAccountRequest) (core.NewAccountResponse, error) {

	ui.mu.Lock()
	defer ui.mu.Unlock()

	fmt.Printf("-------- New Account request--------------\n\n")
	fmt.Printf("A request has been made to create a new account. \n")
	fmt.Printf("Approving this operation means that a new account is created,\n")
	fmt.Printf("and the address is returned to the external caller\n\n")
	showMetadata(request.Meta)
	return core.NewAccountResponse{Approved: false}, nil
}

// ShowError displays error message to user
func (ui *HeadlessConfirmUI) ShowError(message string) {
	fmt.Printf("## Error \n%s\n", message)
	fmt.Printf("-------------------------------------------\n")
}

// ShowInfo displays info message to user
func (ui *HeadlessConfirmUI) ShowInfo(message string) {
	fmt.Printf("## Info \n%s\n", message)
}

func (ui *HeadlessConfirmUI) OnApprovedTx(tx ethapi.SignTransactionResult) {
	fmt.Printf("Transaction signed:\n ")
	if jsn, err := json.MarshalIndent(tx.Tx, "  ", "  "); err != nil {
		fmt.Printf("WARN: marshalling error %v\n", err)
	} else {
		fmt.Println(string(jsn))
	}
}

func (ui *HeadlessConfirmUI) OnSignerStartup(info core.StartupInfo) {
	fmt.Printf("------- Signer info -------\n")
	for k, v := range info.Info {
		fmt.Printf("* %v : %v\n", k, v)
	}
}
