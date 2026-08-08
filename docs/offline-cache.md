# Offline cache

The offline cache is a mirror of the raw `.apk` files a build uses, kept so that
a build with a fully pinned configuration can be repeated later with no index and
no network access.

This document covers using it from the Go library.
For the on-disk layout, the verification model and the guarantees it does and
does not give, see [CACHE.md](../pkg/apk/docs/CACHE.md).
From the command line, `--offline-cache` is available on `apko build`,
`apko publish` and `apko lock`, and `--offline` on `apko build` and
`apko publish`.
`apko lock` can only populate a cache, since locking resolves by definition.

## The two modes

`build.WithOfflineCache(dir)` on its own **populates**: the build resolves against
the index as usual and mirrors every apk it uses into `dir`.

Adding `build.WithOffline(true)` makes `dir` the **only** source of packages: no
index is read and no network request is made.
Every package must then be pinned to an exact version, and the list must be the
complete transitive closure, because there is no index to resolve against.

The offline cache is separate from `build.WithCache`, which stores apks pre-split
into their component sections and is not usable as a standalone source of apks.
Both can be enabled at once.

## Populating a cache

```go
import (
	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
)

const offlineDir = "/path/to/mirror"

bc, err := build.New(ctx, apkfs.NewMemFS(),
	build.WithImageConfiguration(ic),
	build.WithArch(types.ParseArchitecture("amd64")),
	build.WithCache(cacheDir, false, apk.NewCache(true)),
	build.WithOfflineCache(offlineDir),
)
if err != nil {
	return err
}
if _, _, err := bc.BuildLayer(ctx); err != nil {
	return err
}
```

Afterwards `offlineDir` holds each apk, a `.apk.Q1` sidecar recording the
checksum the index reported for it, and the signing keys under `keys/`.

## Capturing the pinned closure

An offline build needs the full closure, pinned, and **in install order**.
`InstalledPackages` reports packages in the order they were installed, so it is
the right source for that list:

```go
installed, err := bc.InstalledPackages()
if err != nil {
	return err
}
pinned := make([]string, 0, len(installed))
for _, p := range installed {
	pinned = append(pinned, p.Name+"="+p.Version)
}
```

Order matters because offline builds install in the order listed, and that
decides which package wins when two of them write the same path.
It shows up in the mtimes of shared directories and in the order of
`/usr/lib/apk/db/installed`.

## Building offline

```go
offlineIC := ic
offlineIC.Contents.Packages = pinned

obc, err := build.New(ctx, apkfs.NewMemFS(),
	build.WithImageConfiguration(offlineIC),
	build.WithArch(types.ParseArchitecture("amd64")),
	build.WithOffline(true),
	build.WithOfflineCache(offlineDir),
)
if err != nil {
	return err
}
if _, _, err := obc.BuildLayer(ctx); err != nil {
	return err
}
```

Nothing else changes: the repositories and keyring in the configuration stay as
they are, and the remote keyring entries are served from the cache's `keys/`
directory rather than fetched.

## Reproducing a build byte for byte

Given the closure in install order, an offline build reproduces an ordinary build
exactly.
There is one thing to get right: the build you are comparing against must record
the same package set.
`build.New` on its own leaves `Contents.Packages` as written, so an unpinned
reference build and a pinned offline build differ in `/etc/apko.json`.

`apko build` avoids this by resolving the configuration first, and a library
caller should do the same with `build.LockImageConfiguration`:

```go
configs, _, err := build.LockImageConfiguration(ctx, ic,
	build.WithOfflineCache(offlineDir),
)
if err != nil {
	return err
}
resolved, ok := configs["amd64"] // keyed by types.Architecture.String(), plus "index"
if !ok {
	return fmt.Errorf("no resolved config for amd64")
}
```

Build the reference image from `*resolved`, then the offline image from the same
configuration with `Contents.Packages` replaced by `pinned`.
Both then record the same sorted package set, and the resulting layers are
identical.

## Multiple architectures

One cache directory serves every architecture, because the architecture is part
of each apk's path.

Pinned versions are not shared, though: `Contents.Packages` applies to whichever
architecture is being built, so a package at different versions per architecture
cannot be expressed in one list.
Build each architecture from its own configuration, which is what
`build.LockImageConfiguration` returns.

## Using the apk library directly

`pkg/apk/apk` has the same option, which populates and verifies the mirror:

```go
a, err := apk.New(ctx,
	apk.WithFS(fs),
	apk.WithArch("x86_64"),
	apk.WithCache(cacheDir, false, apk.NewCache(true)),
	apk.WithOfflineCache(offlineDir),
)
```

The index-free install path itself lives in `pkg/build`, so combining
`apk.WithOfflineCache` with `apk.WithOffline` at this layer only disables
populating.
To install from a mirror at this layer, locate the packages yourself and pass
them to `InstallPackages`:

```go
path, err := apk.OfflineCachePath(offlineDir, apk.APKURL(repo, arch, name, version))
if err != nil {
	return err
}
checksum, err := apk.ReadOfflineChecksum(path)
if err != nil {
	return err
}
```

`path` and `checksum` are the `URL()` and `ChecksumString()` of an
`apk.InstallablePackage`, whose third method is `PackageName()`.
Passing the local path as the URL is what makes the install read from disk.

## Limitations

* The pinned list must be the complete transitive closure.
  A missing dependency produces a broken image, not an error, because there is no
  dependency graph to check against.
* The guarantee is "these are the bytes the index vouched for when the cache was
  populated", not "these bytes are currently signed by the repository key".
  Individual apk signatures are not verified against the keyring.
* Local (`file://` or path) repositories and base images are not supported
  offline, as both resolve packages through an index.
* Version ranges, tilde matches, repository pins (`@tag`) and virtuals (`so:`,
  `cmd:`) are refused offline, since resolving them needs the index.
* A lockfile and an offline build are two ways to pin the same thing, so
  combining them is an error rather than one silently winning.
