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

package libfd

import (
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"syscall"

	"github.com/pkg/errors"
)

// FromDevIno - create FD from (Dev,Ino) - only works if we already have a file open for (Dev,Ino)
func FromDevIno(dev, ino uint64) (*FD, error) {
	fis, err := ioutil.ReadDir("/proc/self/fd/")
	if err != nil {
		return nil, err
	}
	for _, fi := range fis {
		// You may be asking yourself... why not just use fi.Sys().(*syscall.Stat_t).Ino, nil
		// The answer is because /proc/self/newFD/${newFD} is a *link* to the file, with its own distinct Inode
		fd64, err := strconv.ParseUint(fi.Name(), 10, 64)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		newFD, err := FromFD(uintptr(fd64))
		if err == nil && newFD.Dev == dev && newFD.Ino == ino {
			// Create an inode from the FD
			newFD, err = FromFD(uintptr(fd64))
			// If we fail or the inode doesn't match our needs (because we may be racing with someone else closing it and opening a new one)
			// Then keep trying
			if err != nil || newFD.Dev != dev || newFD.Ino != ino {
				continue
			}
			return newFD, nil
		}
	}
	return nil, errors.Errorf("cannot find FDUintptr in /proc/%d/FDUintptr/* for dev %d inode %d", os.Getpid(), dev, ino)
}

// FromFD - makes an FD from a uintptr for underlying file descriptor.  Note: makes a copy so will survive close of the original file descriptor
func FromFD(fdUintptr uintptr) (*FD, error) {
	// Duplicate the FDUintptr to make sure it doesn't disappear under us
	var errno syscall.Errno
	fdUintptr, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fdUintptr, uintptr(syscall.F_DUPFD), 0)
	if errno != 0 {
		return nil, &errno
	}
	// Stat the FDUintptr to get its newFD info
	var stat syscall.Stat_t
	err := syscall.Fstat(int(fdUintptr), &stat)
	if err != nil {
		return nil, err
	}
	newFD := &FD{
		Dev:       stat.Dev,
		Ino:       stat.Ino,
		FDUintptr: fdUintptr,
	}
	runtime.SetFinalizer(newFD, func(fd *FD) {
		_ = fd.Close()
	})
	return newFD, nil
}
