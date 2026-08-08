# Cache

The apk library has the option to cache apk files when downloading. This can provide dramatic speedups
when installing packages, especially when you have a large number of packages to install.

This is completely independent of the target FS where you install the packages themselves. You might have multiple
install runs, all using similar packages. For example, if you need `busybox-1.36.2-r0.apk` for multiple installs,
you only would need to download it once.

The cache is **not** enabled by default. It only is enabled by providing the [WithCache()](../apk/options.go) option to the `New()` function.

## Cache Location

The cache location will be in any provided directory. If you wish to use the default directory, you can pass `""` to
the `WithCache()` option:

```go
a, err := apk.New(
    apk.WithCache(""),
)
```

No `WithCache()` option disables use of the cache.

Note that the default changes by platform, and is determined by [os.userCacheDir()](https://pkg.go.dev/os#UserCacheDir).

## Which Repositories are Cache

Only remote repositories are cached. Those referenced using local filesystems, e.g. `./packages/foo`, are not cached, as they provide
no value in caching.

## Cache Structure

The cache directory provided is the root of the cache. Underneath that directory you will find the following structure.

There is a directory for each repository used. Because remote repositories can contain invalid directory characters,
the name is URL-encoded. For example, a repository `https://dl-cdn.alpinelinux.org/alpine/v3.14/main` would be encoded as
`https%3A%2F%2Fdl-cdn.alpinelinux.org%2Falpine%2Fv3.14%2Fmain`

Underneath each repository directory is a directory that looks identical to the repository. There is a directory for each
architecture, inside of which is an `.apk` file for each package.

When a file is retrieved, if available, the [etag](https://en.wikipedia.org/wiki/HTTP_ETag) header is saved
alongside the file. if it is available, it is saved in a file `<filename>.etag`.
This is used to determine if the file has changed.

Behaviour if no local etag is available depends on how it was called:

* `APKINDEX.tar.gz` - we assume that it can change, and thus no etag found locally means always retrieve it.
* `.apk` files - we assume that they do not change, and thus no etag found locally means the file is accepted as is.

# Offline Cache

For a task-oriented guide to using this from Go, including populating a cache and
reproducing a build from one, see [offline-cache.md](../../../docs/offline-cache.md).

The cache described above stores apks pre-split into their component sections, so
it is not usable as a standalone source of apks. The *offline cache*, enabled with
[WithOfflineCache()](../apk/options.go) or `--offline-cache`, is a separate mirror
of the original `.apk` files, laid out the way the repository serves them:

```
<dir>/<host>/<repo path>/<arch>/<name>-<version>.apk
<dir>/<host>/<repo path>/<arch>/<name>-<version>.apk.Q1
<dir>/keys/<name>.rsa.pub
```

Unlike the cache above, the repository component is not URL-encoded, so the
directory can be populated from or compared against an ordinary apk mirror. The
scheme is dropped; a host and port are kept as-is.

The `.Q1` sidecar records the checksum the repository index reported for that apk.
It is needed because the checksum is a hash of a section *of* the apk, so
recomputing it from the file proves only that the file is internally consistent.
The sidecar is meaningful because it was written while the index was trusted.

## Populating

Given only `WithOfflineCache()`, a build resolves against the index as usual and
mirrors each apk it uses into the directory. An apk already present is read from
there rather than re-downloaded, and is verified against the index on every run.
A repository that publishes different content under a name and version already in
the cache is therefore an error rather than a silent divergence, which also makes
this a way to detect a package rebuilt without an epoch bump.

## Building offline

Combined with `WithOffline()`, the directory becomes the only source of packages:
no index is read and no network request is made. That has three consequences.

* Every package must be pinned to an exact version (`name=1.2.3-r4`). Ranges,
  tilde matches, repository pins (`@tag`) and virtuals (`so:`, `cmd:`) are all
  refused, because resolving them needs the index.
* There is no dependency graph, so the package list must be the **complete
  transitive closure**. A missing dependency yields a broken image, not an error.
* Packages are installed in the order they are listed, and that order decides
  which package wins when two write the same path (it shows up in the mtimes
  of shared directories and in the order of `/usr/lib/apk/db/installed`). Listing
  a resolved closure in resolution order therefore reproduces the image an
  ordinary build would produce, byte for byte. `/etc/apko.json` records the
  package set sorted, as a resolving build does, rather than in the configured
  order, so that the record does not itself introduce a difference.

The guarantee an offline build gives is "these are the bytes the index vouched for
when the cache was populated", not "these bytes are currently signed by the
repository key": individual apk signatures are not verified against the keyring.

Local (`file://` or path) repositories and base images are not supported offline,
as both resolve packages through an index.
