// Copyright 2022, 2023 Chainguard, Inc.
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

package sbom

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

func TestReadPackageIndex(t *testing.T) {
	sampleDB := `
C:Q1Deb0jNytkrjPW4N/eKLZ43BwOlw=
P:musl
V:1.2.2-r7
A:x86_64
S:383152
I:622592
T:the musl c library (libc) implementation
U:https://musl.libc.org/
L:MIT
o:musl
m:Pkg Author <user@domain.com>
t:1632431095
c:bf5bbfdbf780092f387b7abe401fbfceda90c84d
p:so:libc.musl-x86_64.so.1=1
F:lib
R:ld-musl-x86_64.so.1
a:0:0:755
Z:Q12adwqQOjo9dFl+VJD2Ecd901vhE=
R:libc.musl-x86_64.so.1
a:0:0:777
Z:Q17yJ3JFNypA4mxhJJr0ou6CzsJVI=

C:Q1UQjutTNeqKQgMlKQyyZFnumOg3c=
P:libretls
V:3.3.4-r2
A:x86_64
S:29183
I:86016
T:port of libtls from libressl to openssl
U:https://git.causal.agency/libretls/
L:ISC AND (BSD-3-Clause OR MIT)
o:libretls
m:Pkg Author <user@domain.com>
t:1634364270
c:670bf5a8cc5bc605eede8ca2fd55b50a5c9f8660
D:ca-certificates-bundle so:libc.musl-x86_64.so.1 so:libcrypto.so.1.1 so:libssl.so.1.1
p:so:libtls.so.2=2.0.3
F:usr
F:usr/lib
R:libtls.so.2
a:0:0:777
Z:Q1nNEC9T/t6W+Ecm0DxqMUnRvcT6k=
R:libtls.so.2.0.3
a:0:0:755
Z:Q1/KAM0XSmA+YShex9ZKehdaf+mjw=

`
	fsys := apkfs.NewMemFS()
	require.NoError(t, fsys.MkdirAll(filepath.Dir(packageIndexPath), os.FileMode(0o644)))
	require.NoError(t, fsys.WriteFile(packageIndexPath, []byte(sampleDB), os.FileMode(0o644)))

	pkg, err := ReadPackageIndex(fsys)
	require.NoError(t, err)
	require.NotNil(t, pkg)
	require.Len(t, pkg, 2)
}
