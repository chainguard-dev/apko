# Cache

The apk library has the option to cache apk files when downloading. This can provide dramatic speedups
when installing packages, especially when you have a large number of packages to install.

This is completely independent of the target FS where you install the packages themselves. You might have multiple
install runs, all using similar packages. For example, if you need `busybox-1.36.2-r0.apk` for multiple installs,
you only would need to download it once.

The cache is **not** enabled by default. It only is enabled by providing the [WithCache()](./pkg/apk/options.go) option to the `New()` function.

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
