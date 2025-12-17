// Copyright 2025 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlightCache(t *testing.T) {
	s := newFlightCache[string, int]()
	var called int
	r1, err := s.Do("test", func() (int, error) {
		called++
		return 42, nil
	})
	require.NoError(t, err)
	require.Equal(t, 42, r1)

	r2, err := s.Do("test", func() (int, error) {
		called++
		return 1337, nil
	})
	require.NoError(t, err)
	require.Equal(t, r1, r2)
	require.Equal(t, 1, called, "Function should only be called once")

	s.Forget("test")

	r3, err := s.Do("test", func() (int, error) {
		called++
		return 1337, nil
	})
	require.NoError(t, err)
	require.Equal(t, 1337, r3)
	require.Equal(t, 2, called, "Function should be called twice, once before and once after Forget")

	differentKey, err := s.Do("test2", func() (int, error) {
		return 7, nil
	})
	require.NoError(t, err)
	require.Equal(t, 7, differentKey)
}

func TestFlightCacheCachesNoErrors(t *testing.T) {
	s := newFlightCache[string, int]()
	var called int
	_, err := s.Do("test", func() (int, error) {
		called++
		return 42, assert.AnError
	})
	require.ErrorIs(t, assert.AnError, err)

	r2, err := s.Do("test", func() (int, error) {
		called++
		return 1337, nil
	})
	require.NoError(t, err)
	require.Equal(t, 1337, r2)
	require.Equal(t, 2, called, "Function should be called twice, once for the error and once for the success")
}
