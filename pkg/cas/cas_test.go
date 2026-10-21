// Copyright 2026 Chainguard, Inc.
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

package cas_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/cas"
)

func readAll(t *testing.T, s cas.Store, d cas.Digest) string {
	t.Helper()
	r, err := s.OpenBlob(d)
	require.NoError(t, err)
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(b)
}

func TestDigestRoundTrip(t *testing.T) {
	d := cas.Of([]byte("hello"))
	require.Equal(t, "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", d.String())

	got, err := cas.ParseDigest(d.String())
	require.NoError(t, err)
	require.Equal(t, d, got)

	for _, bad := range []string{"2cf24d", "sha256:zz", "sha256:2cf24d"} {
		_, err := cas.ParseDigest(bad)
		require.Error(t, err, bad)
	}
}

func TestMemory(t *testing.T) {
	m := cas.NewMemory()
	d := m.Put([]byte("hello"))
	require.Equal(t, cas.Of([]byte("hello")), d)
	require.Equal(t, "hello", readAll(t, m, d))

	require.Empty(t, readAll(t, m, cas.Empty))

	_, err := m.OpenBlob(cas.Of([]byte("missing")))
	require.ErrorIs(t, err, cas.ErrNotFound)
}

func TestUnion(t *testing.T) {
	a, b := cas.NewMemory(), cas.NewMemory()
	da, db := a.Put([]byte("from a")), b.Put([]byte("from b"))

	u := cas.NewUnion()
	u.Add(da, a)
	u.Add(db, b)
	require.Equal(t, "from a", readAll(t, u, da))
	require.Equal(t, "from b", readAll(t, u, db))

	// The first route wins; a later store for the same digest is ignored.
	u.Add(da, cas.NewMemory())
	require.Equal(t, "from a", readAll(t, u, da))

	_, err := u.OpenBlob(cas.Of([]byte("unrouted")))
	require.ErrorIs(t, err, cas.ErrNotFound)
}
