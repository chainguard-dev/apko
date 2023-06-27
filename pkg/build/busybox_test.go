package build

import (
	"strings"
	"testing"

	impl "github.com/chainguard-dev/go-apk/pkg/apk"
	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	"github.com/stretchr/testify/require"
	"gitlab.alpinelinux.org/alpine/go/repository"

	"chainguard.dev/apko/pkg/options"
)

// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

func TestInstallBusyboxSymlinks(t *testing.T) {
	// these are links that definitely do *not* exist when using the standard files
	fakeLinks := []string{"/bin/foo", "/bin/bar"}
	trueLinks := []string{"/bin/ls", "/bin/grep"}
	pkg := &repository.Package{
		Name:    "busybox",
		Version: "1.36.0", // version that we know exists in busybox_versions.go
	}
	buildBusybox := func(fsys apkfs.FullFS, t *testing.T) {
		var err error
		err = fsys.MkdirAll("/bin", 0755)
		require.NoError(t, err)
		err = fsys.MkdirAll("/etc/busybox-paths.d", 0755)
		require.NoError(t, err)
		err = fsys.WriteFile("/bin/busybox", []byte("busybox"), 0755)
		require.NoError(t, err)
		err = fsys.MkdirAll("/lib/apk/db", 0755)
		require.NoError(t, err)
		pkgLines := impl.PackageToIndex(pkg)
		err = fsys.WriteFile("/lib/apk/db/installed", []byte(strings.Join(pkgLines, "\n")+"\n\n"), 0755)
		require.NoError(t, err)
	}
	t.Run("with busybox-paths manifest", func(t *testing.T) {
		var err error
		di := &buildImplementation{}
		fsys := apkfs.NewMemFS()
		buildBusybox(fsys, t)
		err = fsys.WriteFile("/etc/busybox-paths.d/busybox", []byte(strings.Join(fakeLinks, "\n")), 0755)
		require.NoError(t, err)
		err = di.InstallBusyboxLinks(fsys, &options.Options{})
		require.NoError(t, err)
		for _, link := range fakeLinks {
			_, err := fsys.Lstat(link)
			require.NoError(t, err)
			target, err := fsys.Readlink(link)
			require.NoError(t, err)
			require.Equal(t, "/bin/busybox", target)
		}
		for _, link := range trueLinks {
			_, err := fsys.Lstat(link)
			require.Error(t, err)
		}
	})
	t.Run("without busybox-paths manifest", func(t *testing.T) {
		var err error
		di := &buildImplementation{}
		fsys := apkfs.NewMemFS()
		buildBusybox(fsys, t)
		err = di.InstallBusyboxLinks(fsys, &options.Options{})
		require.NoError(t, err)
		for _, link := range fakeLinks {
			_, err := fsys.Lstat(link)
			require.Error(t, err, "those links should not exist")
		}
		for _, link := range trueLinks {
			_, err := fsys.Lstat(link)
			require.NoError(t, err)
			target, err := fsys.Readlink(link)
			require.NoError(t, err)
			require.Equal(t, "/bin/busybox", target)
		}
	})
}
