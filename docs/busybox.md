# Busybox

Many images depend on [busybox](https://busybox.net).

`apko` supports busybox. However, rather than running `busybox --install` to generate all of the symlinks,
which would require a runner environment and working out the paths, `apko` installs them directly.

`apko` keeps an in-program list of symlinks for each supported version of busybox. At the end of the
installation process, if it finds `/bin/busybox`, it then looks in the apk installed database at
`/usr/lib/apk/db/installed` and determines which version of busybox is installed. It simplifies that
version to the basic semver, e.g. v1.36.1-r3 becomes 1.36.1. It then finds that version in its
own list of symlinks.

If it cannot find that version, it will fall back to the latest version it has in its list.

## Supported Versions

`apko` tries to support all semver versions, including major, minor and patch, but not release candidates or
other such subversions, from 1.32.1 up. This is set in [busybox_gen.go](../pkg/build/busybox_gen.go).

## Generating Symlinks

To regenerate the symlinks, run the following from the repository root:

```sh
go generate -tags busybox_versions ./pkg/build/busybox_gen.go
```

This will generate `pkg/build/busybox_versions.go`, which will be compiled into the program.

You do **not** need to rerun the generation with each compile; only if you want to update the list of versions
and their symlinks.

It is a fairly expensive process, downloading the entire busybox git repository, and then processing it.

To prevent that happening with each `go generate`, it is restricted to the tags shown above.
