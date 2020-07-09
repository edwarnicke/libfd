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
	"syscall"
	"testing"

	"github.com/edwarnicke/libfd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromDevIno(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "")
	require.NoError(t, err)
	defer func() { _ = tmpFile.Close() }()
	fi, err := tmpFile.Stat()
	require.NoError(t, err)
	stat, ok := fi.Sys().(*syscall.Stat_t)
	assert.True(t, ok)
	testData := []byte("test")
	n, err := tmpFile.Write([]byte("test"))
	require.NoError(t, err)
	require.Equal(t, len(testData), n)
	fd, err := libfd.FromDevIno(stat.Dev, stat.Ino)
	require.NoError(t, err)
	defer func() { assert.NoError(t, fd.Close()) }()
	assert.NotEqual(t, tmpFile.Fd(), fd.FDUintptr)
	file, err := fd.ToFile()
	require.NoError(t, err)
	buf := make([]byte, len(testData))
	n, err = file.ReadAt(buf, 0)
	require.NoError(t, err)
	require.Equal(t, len(testData), n)
	require.Equal(t, testData, buf)
	require.NotEqual(t, fd.FDUintptr, file.Fd())
}
