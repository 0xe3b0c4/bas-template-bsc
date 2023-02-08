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

//go:build linux
// +build linux

package rpc

import (
	"context"
	"fmt"
	"os"
	"time"

	"sync/atomic"

	"golang.org/x/sys/unix"
)

type VsockConn struct {
	// closed is a flag that indicates whether the Conn has been closed. It is
	closed uint32

	fd *os.File
}

// Close closes the underlying file descriptor for the Conn, which also causes
// all in-flight I/O operations to immediately unblock and return errors. Any
// subsequent uses of Conn will result in EBADF.
func (c *VsockConn) Close() error {
	if atomic.SwapUint32(&c.closed, 1) == 1 {
		// Multiple Close calls.
		return nil
	}

	return os.NewSyscallError("close", c.fd.Close())
}

// Read reads directly from the underlying file descriptor.
func (c *VsockConn) Read(b []byte) (int, error) { return c.fd.Read(b) }

// Write writes directly to the underlying file descriptor.
func (c *VsockConn) Write(b []byte) (int, error) { return c.fd.Write(b) }

// SetWriteDeadline does nothing and always returns nil.
func (c *VsockConn) SetWriteDeadline(t time.Time) error { return c.fd.SetWriteDeadline(t) }

func parseVsockEndpoint(endpoint string) (uint32, uint32, error) {
	// Parse the endpoint into a context ID and port.
	// The endpoint is a string of the form "vsock://cid:port" where cid is the context ID
	// and port is the port number.
	var cid, port uint32
	_, err := fmt.Sscanf(endpoint, "vsock://%d:%d", &cid, &port)
	if err != nil {
		return 16, 8545, err
	}

	return cid, port, nil
}

func newVsockConnection(ctx context.Context, endpoint string) (Conn, error) {
	// Parse the endpoint into a context ID and port.
	// The endpoint is a string of the form "vsock://cid:port" where cid is the context ID
	cid, port, err := parseVsockEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	sa := &unix.SockaddrVM{CID: cid, Port: port}

	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}

	// All Conn I/O is nonblocking for integration with Go's runtime network
	// poller. Depending on the OS this might already be set but it can't hurt
	// to set it again.
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)

		return nil, os.NewSyscallError("setnonblock", err)
	}

	// os.NewFile registers the non-blocking file descriptor with the runtime
	// poller. This is necessary for the Conn to be used with Go's runtime
	//
	// also: https://golang.org/pkg/os/#NewFile
	f := os.NewFile(uintptr(fd), fmt.Sprintf("vsock_%d_%d", cid, port))
	if err != nil {
		return nil, err
	}

	err = unix.Connect(fd, sa)
	if err != nil {
		_ = unix.Close(fd)

		return nil, err
	}

	// Wrap the file descriptor in a VsockConn.
	return &VsockConn{
		closed: 0,
		fd:     f,
	}, nil
}

// DialVsock create a new vsock client that connects to the given endpoint. The endpoint only works on Linux.
// The endpoint is a string of the form "cid:port" where cid is the context ID and port is the port number.
// The context is used for the initial connection establishment. It does not
// affect subsequent interactions with the client.
func DialVsock(ctx context.Context, endpoint string) (*Client, error) {
	return newClient(ctx, func(ctx context.Context) (ServerCodec, error) {
		conn, err := newVsockConnection(ctx, endpoint)
		if err != nil {
			return nil, err
		}
		return NewCodec(conn), err
	})
}
