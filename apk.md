# apk implementation

`apko` relies on parsing apk packages and installing them in the appropriate directories.

The implementation is in [apk_implementation.go](./pkg/apk/apk_implementation.go). Interface is:

```go
type apkImplementation interface {
	// InitDB initializes the APK database and all directories.
	InitDB() error
	// InitKeyring initializes the keyring with the given keyfiles. The first argument, keyfiles, is a list of
	// keyfile locations. If present, they override the default keyfiles. The second argument, extraKeyfiles, is a list
	// of files to append to the existing ones.
	// Can provide file locations or URLs.
	InitKeyring(keyfiles, extraKeyfiles []string) error
	// SetWorld set the list of packages in the world file. Replaces any existing ones.
	SetWorld(packages []string) error
	// GetWorld get the list of packages in the world file.
	GetWorld() ([]string, error)
	// FixateWorld use the world file to set the state of the system, including any dependencies.
	FixateWorld(cache, updateCache, executeScripts bool, sourceDateEpoch *time.Time) error
	// SetRepositories sets the repositories to use. Replaces any existing ones.
	SetRepositories(repos []string) error
	// GetRepositories gets the list of repositories in use.
	GetRepositories() ([]string, error)
	// GetInstalled gets the list of installed packages.
	GetInstalled() ([]*apkimpl.InstalledPackage, error)
	// ListInitFiles lists the directories and files that are installed via InitDB
	ListInitFiles() []tar.Header
}
```

Note that all of these are plain-vanilla apk functions; there is nothing "apko-specific" about them.

The actual implementation of that interface is in [pkg/apk/impl/](./pkg/apk/impl/). The intent is either to upstream those
to maintenance by the apk team, e.g. at [https://gitlab.alpinelinux.org/alpine/go](https://gitlab.alpinelinux.org/alpine/go),
or, if the above is not an appropriate place, to separate it into a standalone apk-go library.

The entire structure of [pkg/apk/impl/](./pkg/apk/impl/) is built to be completely standalone, and should be replaceable
without affecting any other parts of `apko`.

## Accounting for Functional Limitations

Certain functions within installation of packages or the database installation work differently, depending on whether the
one executing the commands is root or not, or is on a filesystem that supports certain features. For example, Windows does not have symlinks,
some memfs implementations do not support any kinds of links, and running as non-root will cause `chown` to fail.

For all of the above, `apko` does the following. Much of this is possible because the result is a tar file, and the tar file
has support for all of these features.

1. Ignore `chown`/`chmod` errors, while adding overrides to the tar file headers.
1. Ignore symlink/hardlink creation errors, while adding entries for them to the tar file headers.
1. Ignore `mknod` errors, while adding entries for them to the tar file headers.
1. Ensure that the correct character devices exist in the tar stream, even if the apk `InitDB()` could not create them.

In general, when running `apk --initdb`, it tries to create character devices. If it cannot, for example, if the user
does not have sufficient permissions, it bypasses creating them. `apko` does the same, and accounts for it by adding
them to the final layer tar file.

## Passing Overrides and File Information

This implementation relies heavily on `tar.Header` to pass information around. If it needs overrides or additional
file information, `tar.Header` conveniently has all of the fields we need. We very well could use another structure
or interface; this was chosen for its universality and convenience.

## Virtual Filesystem

The implementation uses a virtual filesystem throughout, in order to unify and simplify access. It is inspired by
[fs.FS](https://golang.org/pkg/io/fs/#FS), but does not use it since `fs.FS` is read-only.

In order to support read-write, the implementation includes [rwfs](./pkg/apk/impl/rwfs/), which is a read-write filesystem interface, extending:

* [fs.FS](https://golang.org/pkg/io/fs/#FS)
* [fs.StatFS](https://golang.org/pkg/io/fs/#StatFS)
* [fs.ReadDirFS](https://golang.org/pkg/io/fs/#ReadDirFS)
* [fs.ReadFileFS](https://golang.org/pkg/io/fs/#ReadFileFS)

as well as requirements for `Mkdir`/`MkdirAll`, `OpenFile`, `WriteFile`, `Symlink` and `Mknod`.

For testing, the implementation uses [memfs](./pkg/apk/impl/memfs/), which is an extension of
the memory-based filesystem implementation [memfs](github.com/blang/vfs/memfs), including features to implement the full `rwfs`.

This turned out to be very similar in structure to [pkg/vfs](./pkg/vfs/), with a bit of additional functionality,
It is inside of `pkg/apk/impl/`.
 
A potential alternate implementation of VFS is [https://github.com/spf13/afero](https://github.com/spf13/afero).


