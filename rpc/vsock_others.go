// Copyright 2023 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

//go:build !linux
// +build !linux

package rpc

import "context"

var ErrNotSupportPlatform = errors.New("vsock: not supported on this platform")

// DialVsock create a new vsock client that connects to the given endpoint. The endpoint only works on Linux.
// The endpoint is a string of the form "vscok://cid:port" where cid is the context ID and port is the port number.
// The context is used for the initial connection establishment. It does not
// affect subsequent interactions with the client.
func DialVsock(ctx context.Context, endpoint string) (*Client, error) {
	return nil, ErrNotSupportPlatform
}

// VsockListen will create a vsock on the given endpoint.
func VsockListen(endpoint string) (net.Listener, error) {
	return nil, ErrNotSupportPlatform
}
