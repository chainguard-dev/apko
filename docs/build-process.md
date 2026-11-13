# apko Build Process

apko builds an OCI-compliant image, stored in a tar file, that can then be loaded into a container runtime.
The entire build is configured from a declarative file `apko.yaml`, which does not allow the execution of arbitrary
commands. Instead, all content is generated from installing `apk` packages.

The build process is driven by the implementation of the `apko build` command, specifically
[`BuildCmd()`](../internal/cli/build.go#L142).

The entire build process involves laying out the desired files in a temporary working directory, and then
packaging that working directory as an OCI filesystem layer `.tar.gz`. With that layer file in hand,
it can be packaged into an OCI image, and an SBoM can be created.

The process is as follows:

1. Create a temporary working directory.
2. Create a [`build.Context`](../pkg/build/build.go#L52-61). This `Context` contains:
   * The parsed config file into an internal structure [`ImageConfiguration`](../pkg/build/types/types.go#L150-199)
   * The [`s6.Context`](../pkg/s6/s6.go#L23-26), which contains configuration for optionally installing the s6 supervisor to manage the process in the container
   * Build-time options
3. Refresh the `build.Context`, which sets initialization and runtime parameters, such as isolation, working directory, the executor and the s6 context.
4. Build the layer in the working directory, the heart of the build, calling [`build.Context.BuildLayer()`](../pkg/build/build.go#L117-135). This results in the entire laid out filesystem packaged up into a `.tar.gz` file. More detail on this follows later in this document.
5. Generate an SBoM.
6. Generate an OCI image tar file from the single layer `.tar.gz` file in [`oci.BuildImageTarballFromLayer()`](../pkg/build/oci/image.go#L190).

## Layer Build

As described above, after everything is setup, the actual build occurs inside the working directory.
The build is in [`build.Context.BuildLayer()`](../pkg/build/build.go#L117-135), which consists of:

1. `Context.BuildImage()`: building the image

The actual building of the image via `BuildImage()` just wraps [`buildImage()`](../pkg/build/build_implementation.go#L154-246).

It involves several steps:

1. Validate the image configuration. This includes setting defaults.
2. Initialize the apk. This involves setting up the various apk directories inside the working directory.
3. Add additional tags for apk packages.
4. `MutateAccounts()`: Create users and groups.
5. Set file and directory permissions.
6. Set the symlinks for busybox, as busybox is a single binary which determines what action to take based on the invoked path.
7. Update ldconfig.
8. Create the `/etc/os-release` file.
9. If s6 is used for supervision, install it and create its configuration files.

Note that all of the steps involve some file manipulation.

* In the case of simply laying out files or changing permissions, this is straightforward and performed in the working directory.
* In the case of apk commands, it uses the [pkg/apk/apk/implementation](../pkg/apk/apk/implementation.go) implementation to lay out files directly.
* In the case of `chown`/`chmod`, if it cannot do so directly - either because the underlying filesystem does not support it or because it is not running as root - it ignores the errors and keeps track of the intended ownership and permissions, adding them to the final layer tar stream.
* In the case of `ldconfig`, it replicates the equivalent functionality by parsing the library ELF headers and creating the symlinks.
* In the case of `busybox`, it creates symlinks to the busybox binary, based on a fixed list.
* In the case of character devices, if it cannot do so directly - either because the underlying filesystem does not support it or because it is not running as root - it ignores the errors and keeps track of the intended files, adding them to the final layer tar stream.
