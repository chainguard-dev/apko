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
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestFlightCache(t *testing.T) {
	s := newFlightCache[string, int](2)
	var called int
	r1, _, err := s.Do("test", func() (int, error) {
		called++
		return 42, nil
	})
	require.NoError(t, err)
	require.Equal(t, 42, r1)

	r2, _, err := s.Do("test", func() (int, error) {
		called++
		return 1337, nil
	})
	require.NoError(t, err)
	require.Equal(t, r1, r2)
	require.Equal(t, 1, called, "Function should only be called once")

	s.Forget("test")

	r3, _, err := s.Do("test", func() (int, error) {
		called++
		return 1337, nil
	})
	require.NoError(t, err)
	require.Equal(t, 1337, r3)
	require.Equal(t, 2, called, "Function should be called twice, once before and once after Forget")

	differentKey, _, err := s.Do("test2", func() (int, error) {
		return 7, nil
	})
	require.NoError(t, err)
	require.Equal(t, 7, differentKey)
}

func TestFlightCacheCachesNoErrors(t *testing.T) {
	s := newFlightCache[string, int](1)
	var called int
	_, _, err := s.Do("test", func() (int, error) {
		called++
		return 42, assert.AnError
	})
	require.ErrorIs(t, assert.AnError, err)

	r2, _, err := s.Do("test", func() (int, error) {
		called++
		return 1337, nil
	})
	require.NoError(t, err)
	require.Equal(t, 1337, r2)
	require.Equal(t, 2, called, "Function should be called twice, once for the error and once for the success")
}

func TestFlightCacheReportsHits(t *testing.T) {
	s := newFlightCache[string, int](1)

	value, hit, err := s.Do("test", func() (int, error) {
		return 42, nil
	})
	require.NoError(t, err)
	require.False(t, hit)
	require.Equal(t, 42, value)

	value, hit, err = s.Do("test", func() (int, error) {
		return 1337, nil
	})
	require.NoError(t, err)
	require.True(t, hit)
	require.Equal(t, 42, value)
}

func TestFlightCacheCoalescesCalls(t *testing.T) {
	s := newFlightCache[string, int](1)

	var called atomic.Int32
	var mux sync.Mutex
	mux.Lock() // Lock to ensure the call below hangs until we unlock.

	var eg errgroup.Group
	for range 10 {
		eg.Go(func() error {
			_, _, err := s.Do("test", func() (int, error) {
				mux.Lock() // Hangs until the unlock below.
				called.Add(1)
				return 42, nil
			})
			return err
		})
	}
	mux.Unlock() // Allow the calls to proceed.
	require.NoError(t, eg.Wait())

	require.EqualValues(t, 1, called.Load(), "Function should only be called once")
}

func TestFlightCacheForgetFunc(t *testing.T) {
	s := newFlightCache[string, int](3)

	for k, v := range map[string]int{"a-1": 1, "a-2": 2, "b-1": 3} {
		_, _, err := s.Do(k, func() (int, error) { return v, nil })
		require.NoError(t, err)
	}

	// Forget all keys starting with "a-".
	s.ForgetFunc(func(k string) bool {
		return strings.HasPrefix(k, "a-")
	})

	// "a-*" keys should be evicted, so new values are computed.
	r, _, err := s.Do("a-1", func() (int, error) { return 100, nil })
	require.NoError(t, err)
	require.Equal(t, 100, r)

	r, _, err = s.Do("a-2", func() (int, error) { return 200, nil })
	require.NoError(t, err)
	require.Equal(t, 200, r)

	// "b-1" should still be cached.
	r, _, err = s.Do("b-1", func() (int, error) { return 999, nil })
	require.NoError(t, err)
	require.Equal(t, 3, r, "b-1 should still return the cached value")
}

func TestFlightCacheEvictsLeastRecentlyUsed(t *testing.T) {
	s := newFlightCache[string, int](2)

	for _, item := range []struct {
		key   string
		value int
	}{{"a", 1}, {"b", 2}} {
		_, _, err := s.Do(item.key, func() (int, error) { return item.value, nil })
		require.NoError(t, err)
	}

	_, hit, err := s.Do("a", func() (int, error) { return 10, nil })
	require.NoError(t, err)
	require.True(t, hit)

	_, _, err = s.Do("c", func() (int, error) { return 3, nil })
	require.NoError(t, err)

	value, hit, err := s.Do("b", func() (int, error) { return 20, nil })
	require.NoError(t, err)
	require.False(t, hit)
	require.Equal(t, 20, value)
}
