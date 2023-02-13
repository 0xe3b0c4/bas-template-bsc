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
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"sync/atomic"

	"github.com/ethereum/go-ethereum/log"
	"golang.org/x/sys/unix"
)

// also: https://github.com/mdlayher/socket/blob/41a913f3993a902e7e2644b09110a65e3185158c/conn.go
// checkErr check if the error is a temporary error.
func vsockNoReady(err error) bool {
	switch err {
	case unix.EAGAIN, unix.EINPROGRESS, unix.EINTR:
		// When a socket is in non-blocking mode, we might see a variety of errors:
		//  - EAGAIN: most common case for a socket read not being ready
		//  - EINPROGRESS: reported by some sockets when first calling connect
		//  - EINTR: system call interrupted, more frequently occurs in Go 1.14+
		//    because goroutines can be asynchronously preempted
		//
		// Return false to let the poller wait for readiness. See the source code
		// for internal/poll.FD.RawRead for more details.
		return true
	default:
		// Ready regardless of whether there was an error or no error.
		return false
	}
}

func vsocket() (int, error) {
	var (
		fd  int
		err error
	)

	for {
		fd, err = unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
		switch {
		case err == nil:
			return fd, nil
		case vsockNoReady(err):
			// System call interrupted or not ready, try again.
			continue
		case err == unix.EINVAL, err == unix.EPROTONOSUPPORT:
			// On Linux, SOCK_NONBLOCK and SOCK_CLOEXEC were introduced in
			// 2.6.27. On FreeBSD, both flags were introduced in FreeBSD 10.
			// EINVAL and EPROTONOSUPPORT check for earlier versions of these
			// OSes respectively.
			//
			// Mirror what the standard library does when creating file
			// descriptors: avoid racing a fork/exec with the creation of new
			// file descriptors, so that child processes do not inherit socket
			// file descriptors unexpectedly.
			//
			// For a more thorough explanation, see similar work in the Go tree:
			// func sysSocket in net/sock_cloexec.go, as well as the detailed
			// comment in syscall/exec_unix.go.
			syscall.ForkLock.RLock()
			fd, err = unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
			if err != nil {
				syscall.ForkLock.RUnlock()
				return -1, os.NewSyscallError("socket", err)
			}
			unix.CloseOnExec(fd)
			syscall.ForkLock.RUnlock()

			return fd, nil
		default:
			// Unhandled error.
			return -1, os.NewSyscallError("socket", err)
		}
	}
}

func vsockConnect(fd int, addr *unix.SockaddrVM) error {
	for {
		err := unix.Connect(fd, addr)

		switch {
		case err == nil:
			return nil
		case vsockNoReady(err):
			continue
		default:
			return err
		}
	}
}

func vsockGetsockename(fd int) (*vsockAddr, error) {
	localAddr := &vsockAddr{}

	for {
		lsa, err := unix.Getsockname(fd)

		switch {
		case err == nil:
			if savm, ok := lsa.(*unix.SockaddrVM); ok {
				localAddr.cid = savm.CID
				localAddr.port = savm.Port
			}

			return localAddr, nil
		case vsockNoReady(err):
			continue
		default:
			if err != nil {
				return nil, err
			}
		}
	}
}

// parseVsockEndpoint parses a vsock endpoint string of the form "vsock://cid:port" into
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

type vsockAddr struct {
	cid, port uint32
}

func (va *vsockAddr) Network() string {
	return "vsock"
}

func (va *vsockAddr) String() string {
	return fmt.Sprintf("%d:%d", va.cid, va.port)
}

type vsockConn struct {
	// closed is a flag that indicates whether the Conn has been closed. It is
	closed uint32

	// vsock file descriptor
	fd *os.File

	// localAddr is the local address of the connection.
	localAddr vsockAddr

	// remoteAddr is the remote address of the connection.
	remoteAddr vsockAddr
}

// Close closes the underlying file descriptor for the Conn, which also causes
// all in-flight I/O operations to immediately unblock and return errors. Any
// subsequent uses of Conn will result in EBADF.
func (c *vsockConn) Close() error {
	if atomic.SwapUint32(&c.closed, 1) == 1 {
		// Multiple Close calls.
		return nil
	}

	return os.NewSyscallError("close", c.fd.Close())
}

// Read reads directly from the underlying file descriptor.
func (c *vsockConn) Read(b []byte) (int, error) { return c.fd.Read(b) }

// Write writes directly to the underlying file descriptor.
func (c *vsockConn) Write(b []byte) (int, error) { return c.fd.Write(b) }

// implements net.Conn
func (c *vsockConn) SetDeadline(t time.Time) error {
	return c.fd.SetDeadline(t)
}

func (c *vsockConn) SetReadDeadline(t time.Time) error  { return c.fd.SetReadDeadline(t) }
func (c *vsockConn) SetWriteDeadline(t time.Time) error { return c.fd.SetWriteDeadline(t) }

func (c *vsockConn) LocalAddr() net.Addr {
	return &c.localAddr
}

func (c *vsockConn) RemoteAddr() net.Addr {
	return &c.remoteAddr
}

// newVsockConnection creates a new vsock connect wrap to Conn interface
func newVsockConnection(ctx context.Context, endpoint string) (net.Conn, error) {
	// Parse the endpoint into a context ID and port.
	// The endpoint is a string of the form "vsock://cid:port" where cid is the context ID
	cid, port, err := parseVsockEndpoint(endpoint)
	if err != nil {
		log.Error("vsock endpoint format error", "endpoint", endpoint)

		return nil, err
	}

	fd, err := vsocket()
	if err != nil || fd < 0 {
		log.Error("vsock open failed", "cid", cid, "port", port)

		return nil, err
	}

	sa := &unix.SockaddrVM{CID: cid, Port: port}

	if err := vsockConnect(fd, sa); err != nil {
		_ = unix.Close(fd)
		log.Error("vsock connect failed", "err", err)

		return nil, err
	}

	localAddr, err := vsockGetsockename(fd)
	if err != nil {
		_ = unix.Close(fd)
		log.Error("vsock getsockname failed", "err", err)

		return nil, err
	}

	// os.NewFile registers the non-blocking file descriptor with the runtime
	// poller. This is necessary for the Conn to be used with Go's runtime
	//
	// also: https://golang.org/pkg/os/#NewFile
	f := os.NewFile(uintptr(fd), fmt.Sprintf("vsock_%d_%d", cid, port))
	if err != nil {
		_ = unix.Close(fd)
		log.Error("vsock to file descriptor failed")

		return nil, err
	}

	// Wrap the file descriptor in a VsockConn.
	return &vsockConn{
		closed: 0,
		fd:     f,
		remoteAddr: vsockAddr{
			cid:  cid,
			port: port,
		},
		localAddr: *localAddr,
	}, nil
}

// DialVsock create a new vsock client that connects to the given endpoint. The endpoint only works on Linux.
// The endpoint is a string of the form "cid:port" where cid is the context ID and port is the port number.
// The context is used for the initial connection establishment. It does not
// affect subsequent interactions with the client.
func DialVsock(ctx context.Context, endpoint string) (*Client, error) {
	log.Info("DialVsock", "endpoint", endpoint)

	httpc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return newVsockConnection(ctx, endpoint)
			},
		},
	}

	initctx := context.Background()
	headers := make(http.Header, 2)
	headers.Set("accept", contentType)
	headers.Set("content-type", contentType)
	return newClient(initctx, func(context.Context) (ServerCodec, error) {
		hc := &httpConn{
			client:  httpc,
			headers: headers,
			url:     "http://localhost:8545", // fake url
			closeCh: make(chan interface{}),
		}
		return hc, nil
	})
}

type vsockListener struct {
	// closed is a flag that indicates whether the Conn has been closed. It is
	closed uint32

	// vsock file descriptor
	fd int

	// listen address
	addr vsockAddr
}

func (l *vsockListener) Accept() (net.Conn, error) {
	fd, sa, err := unix.Accept(l.fd)
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

	remoteAddr := &vsockAddr{}
	if savm, ok := sa.(*unix.SockaddrVM); ok {
		remoteAddr.cid = savm.CID
		remoteAddr.port = savm.Port
	}

	// Wrap the file descriptor in a VsockConn.
	return &vsockConn{
		closed:     0,
		fd:         os.NewFile(uintptr(fd), "vsock"),
		remoteAddr: *remoteAddr,
		localAddr:  l.addr,
	}, nil
}

func (l *vsockListener) Close() error {
	if atomic.SwapUint32(&l.closed, 1) == 1 {
		// Multiple Close calls.
		return nil
	}

	return os.NewSyscallError("close", unix.Close(l.fd))
}

func (l *vsockListener) Addr() net.Addr {
	return &l.addr
}

// VsockListen will create a vsock on the given endpoint.
func VsockListen(port uint32) (net.Listener, error) {
	sa := &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}

	fd, err := vsocket()
	if err != nil || fd < 0 {
		return nil, err
	}

	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	return &vsockListener{
		closed: 0,
		fd:     fd,
		addr: vsockAddr{
			cid:  unix.VMADDR_CID_ANY,
			port: port,
		},
	}, nil
}
