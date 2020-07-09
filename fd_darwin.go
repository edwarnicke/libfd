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
	"runtime"
	"syscall"
)

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
		Dev:       uint64(stat.Dev),
		Ino:       stat.Ino,
		FDUintptr: fdUintptr,
	}
	runtime.SetFinalizer(newFD, func(fd *FD) {
		_ = fd.Close()
	})
	return newFD, nil
}
