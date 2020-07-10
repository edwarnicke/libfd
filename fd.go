// Copyright (c) 2020 Cisco and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package libfd provides low level file manipulation
package libfd

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/pkg/errors"
)

// FD - a helpful utility for performing low level actions on a file defined by its Dev and Ino
type FD struct {
	Dev       uint64
	Ino       uint64
	FDUintptr uintptr
}

type syscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

// FromConn - create and FD for the underlying (Dev,Ino) for a net.Conn.  Note: makes a separate file descriptor, so will survive conn.Close
func FromConn(conn net.Conn) (*FD, error) {
	if conn == nil {
		return nil, errors.New("conn cannot be nil")
	}
	if scc, ok := conn.(syscallConn); ok {
		raw, err := scc.SyscallConn()
		if err != nil {
			return nil, err
		}
		return FromSyscallRawConn(raw)
	}
	return nil, errors.Errorf("unable to extract raw FDUintptr to find Inode from %+v due to lack of syscallConn() (syscall.RawConn, error) method", conn)
}

// FromFilename - create an FD from a filename.
func FromFilename(filename string) (*FD, error) {
	file, err := os.Open(filename) // #nosec
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return FromFile(file)
}

// FromFile - create and FD for the underlying (Dev,Ino) for a *os.File.  Note: makes a separate file descriptor, so will survive file.Close
func FromFile(file *os.File) (*FD, error) {
	if file == nil {
		return nil, errors.New("file cannot be nil")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	return FromSyscallRawConn(raw)
}

// FromSyscallRawConn - create and FD for the underlying (Dev,Ino) for a syscall.RawConn.  Note: makes a separate file descriptor, so will survive Close of the original thing.
func FromSyscallRawConn(raw syscall.RawConn) (*FD, error) {
	if raw == nil {
		return nil, errors.New("raw cannot be nil")
	}
	fdch := make(chan uintptr, 1)
	err := raw.Control(func(fd uintptr) {
		fdch <- fd
	})
	if err != nil {
		return nil, err
	}
	return FromFD(<-fdch)
}

// ToFile - Returns file for FD
func (fd *FD) ToFile() (*os.File, error) {
	if fd == nil {
		return nil, errors.New("FD receiver cannot be nil")
	}
	newFD, err := fd.Dup()
	if err != nil {
		return nil, err
	}
	return os.NewFile(newFD.FDUintptr, newFD.Filename()), nil
}

// ToConn - returns net.Conn for FD *if* FD represents a socket connection
func (fd *FD) ToConn() (net.Conn, error) {
	if fd == nil {
		return nil, errors.New("FD receiver cannot be nil")
	}
	file, err := fd.ToFile()
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }() // net.FileConn makes a duplicate of the FD... so we are safe to close this one
	return net.FileConn(file)
}

// Close - closes the FD
func (fd *FD) Close() error {
	if fd == nil {
		return errors.New("FD receiver cannot be nil")
	}
	return os.NewFile(fd.FDUintptr, fd.Filename()).Close()
}

// Dup - creates a duplicate of FD with a distinct file descriptor for the same Dev,Inode
func (fd *FD) Dup() (*FD, error) {
	if fd == nil {
		return nil, errors.New("FD receiver cannot be nil")
	}
	return FromFD(fd.FDUintptr)
}

// DupFile - creates a duplicate of FD with a distinct file descriptor for the same Dev,Inode and returns it as an *os.File
func (fd *FD) DupFile() (*os.File, error) {
	if fd == nil {
		return nil, errors.New("FD receiver cannot be nil")
	}
	dupFD, err := fd.Dup()
	if err != nil {
		return nil, err
	}
	return os.NewFile(dupFD.FDUintptr, fmt.Sprintf("/proc/%d/FDUintptr/%d", os.Getpid(), dupFD)), nil
}

// Filename of FD - returns fmt.Sprintf("/proc/%d/FDUintptr/%d", os.Getpid(), fd.FDUintptr)
func (fd *FD) Filename() string {
	if fd == nil {
		return ""
	}
	return fmt.Sprintf("/proc/%d/FDUintptr/%d", os.Getpid(), fd.FDUintptr)
}

// SendTo - Sends this FD as a file descriptor over conn if possible.  Generally only works for UnixConn
func (fd *FD) SendTo(conn net.Conn) error {
	if fd == nil {
		return errors.New("FD receiver cannot be nil")
	}
	if scc, ok := conn.(syscallConn); ok {
		raw, err := scc.SyscallConn()
		if err != nil {
			return err
		}
		fdch := make(chan uintptr, 1)
		err = raw.Control(func(fd uintptr) {
			fdch <- fd
		})
		if err != nil {
			return err
		}
		rights := syscall.UnixRights(int(fd.FDUintptr))
		return syscall.Sendmsg(int(<-fdch), nil, rights, nil, 0)
	}
	return errors.Errorf("unable to extract raw FDUintptr to find Inode from %+v due to lack of syscallConn() (syscall.RawConn, error) method", conn)
}

// RecvFromConn - receives a file descriptor over conn if possibleand returns it as an FD.  Generally only works for UnixConn
func RecvFromConn(conn net.Conn) (*FD, error) {
	if scc, ok := conn.(syscallConn); ok {
		raw, err := scc.SyscallConn()
		if err != nil {
			return nil, err
		}
		fdch := make(chan uintptr, 1)
		err = raw.Control(func(fd uintptr) {
			fdch <- fd
		})
		if err != nil {
			return nil, err
		}
		buf := make([]byte, syscall.CmsgSpace(4))
		_, _, _, _, err = syscall.Recvmsg(int(<-fdch), nil, buf, 0)
		if err != nil {
			return nil, err
		}
		var msgs []syscall.SocketControlMessage
		msgs, err = syscall.ParseSocketControlMessage(buf)
		if err != nil {
			return nil, err
		}
		fds, err := syscall.ParseUnixRights(&msgs[0])
		if err != nil {
			return nil, err
		}
		fd, err := FromFD(uintptr(fds[0]))
		if err != nil {
			return nil, err
		}
		// Close the fd we have just received
		file := os.NewFile(uintptr(fds[0]), "")
		err = file.Close()
		if err != nil {
			return nil, err
		}
		return fd, nil
	}
	return nil, errors.Errorf("unable to extract raw FDUintptr to find Inode from %+v due to lack of syscallConn() (syscall.RawConn, error) method", conn)
}

// FDer - wrapper for things providing ToFD() *FD
type FDer interface {
	ToFD() *FD
}
