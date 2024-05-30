# go-apk

A native go implementation of the functionality of the [Alpine Package Keeper](https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper)
client utility `apk`.

Also includes supporting utilities for working with filesystems, including:

* an interface for a fully functional [fs.FS](https://pkg.go.dev/io/fs#FS) with
read-write, chmod/chown, devices, and symlinks capabilities
* an implementation of that FS in memory, i.e. a memfs
* an implementation of that FS on top of a directory, which uses the memfs for features the underlying disk does not support
* tarball features

Documentation is available at [https://pkg.go.dev/chainguard.dev/apko/pkg/apk](https://pkg.go.dev/chainguard.dev/apko/pkg/apk).

## Usage

```go
import (
    "chainguard.dev/apko/pkg/apk/apk"
    "chainguard.dev/apko/pkg/apk/fs"
)

fsys := fs.NewMemFS()
a, err := apk.New(
		apk.WithFS(fsys),
		apk.WithArch("aarch64"),
	)
a.InitDB("3.16", "3.17") // ensure basic structures and set up the database, fetches keys for those OS versions
a.InitKeyring([]string{"/etc/apk/keyfiles/key1"}, nil)
a.SetRepositories([]string{"https://dl-cdn.alpinelinux.org/alpine/v3.14/main"})
a.SetWorld([]string{"curl", "vim"})    // set the packages in /etc/apk/world
a.FixateWorld()              // install packages based on the contents of /etc/apk/world
```

Wherever possible the methods on `apk` that manipulate data are available standalone,
so you can work with them outside of a given `FullFS`.

## Components

### Filesystems

The native go [fs.FS](https://pkg.go.dev/io/fs#FS) interface is a read-only filesystem
with no support for full capabilities like read-write, let alone symlinks, hardlinks,
chown/chmod, devices, etc.

That makes it useful for reading, but not very useful for cases where you need to lay
down data, like installing packages from a package manager.

`chainguard.dev/apko/pkg/apk/fs` provides a `FullFS` interface that extends the
`fs.FS` interface with full read-write, chmod/chown, devices, and symlinks capabilities.
You can do pretty much anything that you can do with a normal filesystem.

It is fully compliant with [fs.FS](https://pkg.go.dev/io/fs#FS), so you can use it
anywhere an `fs.FS` is required.

It also provides two implementations of that interface:

* `memfs` is an in-memory implementation of `FullFS`. It is fully functional, but remember that it uses memory, so loading very large files into it will hit limits.
* `rwosfs` is an on-disk implementation of `FullFS`. It is fully functional, including capabilities that may not exist on the underlying filesystem, like symlinks, devices, chown/chmod and case-sensitivity. The metadata for every file on disk also is in-memory, enabling those additional capabilities. Contents are not stored in memory.

### Tarball

`chainguard.dev/apko/pkg/apk/tarball` provides a utility to write an [fs.FS](https://pkg.go.dev/io/fs#FS) to a tarball. It is implemented on a `tarball.Context`, which lets
you provide overrides for timestamps, UID/GID, and other features.

### apk

`chainguard.dev/apko/pkg/apk/apk` is the heart of this library. It provides a native go
implementation of the functionality of the
[Alpine Package Keeper](https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper)
with regards to reading repositories, installing packages, and managing a local install.

## Caching

This package provides an option to cache apk packages locally. This can provide dramatic speedups
when installing packages, especially when the package is large or the network is slow and you already have a copy.

It is enabled only when the [WithCache()](./pkg/apk/options.go) option is provided to the `New()` function.

When the cache is enabled, any requested apk files are checked in the cache first, and only downloaded
in the case of a cache miss. The now-cached apk can be used in subsequent calls. To ignore the cache,
simple do not pass `WithCache()` to `New()`.

See [CACHE.md](./docs/CACHE.md) for more details on the cache structure.
