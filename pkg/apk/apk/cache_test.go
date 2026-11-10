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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// TestFlightCacheJoinedCallersRetryAfterFailure checks that a transient
// error is reported only to the caller whose call failed. Callers that
// joined that in-flight call retry with their own call rather than all
// surfacing the same error.
func TestFlightCacheJoinedCallersRetryAfterFailure(t *testing.T) {
	s := newFlightCache[string, int](1)

	var called atomic.Int32
	started := make(chan struct{}) // closed once the first call is in flight
	release := make(chan struct{}) // closed to let the first call fail

	var failures, successes atomic.Int32
	call := func() {
		v, _, err := s.Do("test", func() (int, error) {
			if called.Add(1) == 1 {
				close(started)
				<-release
				return 0, assert.AnError
			}
			return 42, nil
		})
		if err != nil {
			failures.Add(1)
			return
		}
		if v == 42 {
			successes.Add(1)
		}
	}

	var wg sync.WaitGroup
	wg.Go(call)
	<-started // The failing call is now in flight, so every later caller joins it.

	var arrived atomic.Int32
	for range 9 {
		wg.Go(func() {
			arrived.Add(1)
			call()
		})
	}
	for arrived.Load() < 9 {
		runtime.Gosched()
	}
	// The joiners are at or inside Do by now; give them a moment to block
	// on the in-flight call before it is allowed to fail. Without the retry
	// in Do, every joiner would report the first call's error here.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	require.EqualValues(t, 1, failures.Load(), "only the caller that ran the failing call sees its error")
	require.EqualValues(t, 9, successes.Load(), "every other caller retries and succeeds")
	require.GreaterOrEqual(t, called.Load(), int32(2))

	// The failed call must only have evicted its own entry: the successful
	// retry is still cached, so a new caller hits it without another call.
	before := called.Load()
	v, hit, err := s.Do("test", func() (int, error) { return -1, nil })
	require.NoError(t, err)
	require.True(t, hit, "the successful entry stays cached after the failed one is evicted")
	require.Equal(t, 42, v)
	require.Equal(t, before, called.Load())
}

// TestFlightCacheFailedCallEvictsOnlyItsOwnEntry pins the guard in do: a
// call that fails after its entry was replaced must not evict the newer,
// successful entry for the same key.
func TestFlightCacheFailedCallEvictsOnlyItsOwnEntry(t *testing.T) {
	s := newFlightCache[string, int](1)

	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, _, err := s.Do("k", func() (int, error) {
			close(started)
			<-release
			return 0, assert.AnError
		})
		done <- err
	}()
	<-started

	// Replace the in-flight entry with a fresh, successful one.
	s.Forget("k")
	v, hit, err := s.Do("k", func() (int, error) { return 42, nil })
	require.NoError(t, err)
	require.False(t, hit)
	require.Equal(t, 42, v)

	// Now let the old call fail. It owned the evicted entry, not the new one.
	close(release)
	require.ErrorIs(t, <-done, assert.AnError)

	var called bool
	v, hit, err = s.Do("k", func() (int, error) { called = true; return -1, nil })
	require.NoError(t, err)
	require.True(t, hit, "the newer successful entry must survive the old call's failure")
	require.Equal(t, 42, v)
	require.False(t, called)
}
