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

package libfd_test

import (
	"io/ioutil"
	"net"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edwarnicke/libfd"
)

func TestFromFilename(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "")
	require.NoError(t, err)
	defer func() { _ = tmpFile.Close() }()
	fd, err := libfd.FromFilename(tmpFile.Name())
	assert.NotEqual(t, tmpFile.Fd(), fd.FDUintptr)
	defer func() { assert.NoError(t, fd.Close()) }()
	require.NoError(t, err)
	fi, err := tmpFile.Stat()
	require.NoError(t, err)
	stat, ok := fi.Sys().(*syscall.Stat_t)
	assert.True(t, ok)
	assert.EqualValues(t, fd.Ino, stat.Ino)
	assert.EqualValues(t, fd.Dev, stat.Dev)
}

func TestFromConn(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	tmpPath := filepath.Join(tmpDir, "socket")
	listener, err := net.Listen("unix", tmpPath)
	require.NoError(t, err)
	incomingCh := make(chan net.Conn, 1)
	go func() {
		incoming, incomingErr := listener.Accept()
		assert.NoError(t, incomingErr)
		incomingCh <- incoming
	}()
	conn, err := (&net.Dialer{}).Dial("unix", tmpPath)
	require.NoError(t, err)
	fd, err := libfd.FromConn(conn)
	require.NoError(t, err)
	conn2, err := fd.ToConn()
	require.NoError(t, err)
	err = fd.SendTo(conn2)
	require.NoError(t, err)
	incoming := <-incomingCh
	fd2, err := libfd.RecvFromConn(incoming)
	require.NoError(t, err)
	assert.Equal(t, fd.Dev, fd2.Dev)
	assert.Equal(t, fd.Ino, fd2.Ino)
	assert.NotEqual(t, fd.FDUintptr, fd2.FDUintptr)
}

func TestFD_DupFile(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "")
	require.NoError(t, err)
	defer func() { _ = tmpFile.Close() }()
	testData := []byte("test")
	n, err := tmpFile.Write([]byte("test"))
	require.NoError(t, err)
	require.Equal(t, len(testData), n)
	fd, err := libfd.FromFile(tmpFile)
	require.NoError(t, err)
	file, err := fd.DupFile()
	require.NoError(t, err)
	assert.NotEqual(t, file.Fd(), tmpFile.Fd())
	buf := make([]byte, len(testData))
	n, err = file.ReadAt(buf, 0)
	require.NoError(t, err)
	assert.Equal(t, len(testData), n)
	require.Equal(t, testData, buf)
}
