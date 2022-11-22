# apko Build Process

apko builds an OCI-compliant image, stored in a tar file, that can then be loaded into a container runtime.
The entire build is configured from a declarative file `apko.yaml`, which does not allow the execution of arbitrary
commands. Instead, all content is generated from installing `apk` packages.

The build process is driven by the implementation of the `apko build` command, specifically
[`BuildCmd()`](../internal/cli/build.go#L104).

The entire build process involves laying out the desired files in a temporary working directory, and then
packaging that working directory as an OCI filesystem layer `.tar.gz`. With that layer file in hand,
it can be packaged into an OCI image, and an SBoM can be created.

The process is as follows:

1. Create a temporary working directory.
1. Create a [`build.Context`](../pkg/build/build.go#L37-45). This `Context` contains:
   * The path to the config file, default to `apko.yaml`
   * The parsed config file into an internal structure [`ImageConfiguration`](../pkg/build/types/types.go#L55-83)
   * The [`buildImplementation`](../pkg/build/build_implementation.go#L43-59), which is the engine responsible for executing the actual build
   * The [`Executor`](../pkg/exec/exec.go#L26-31), which handles external command execution by the `buildImplementation`
   * The [`s6.Context`](../pkg/s6/s6.go#L23-26), which contains configuration for optionally installing the s6 supervisor to manage the process in the container
   * Build-time options
1. Refresh the `build.Context`, which sets initialization and runtime parameters, such as isolation, working directory, the executor and the s6 context.
1. Build the layer in the working directory, the heart of the build, calling [`build.Context.BuildLayer()`](../pkg/build/build.go#L80-109). This results in the entire laid out filesystem packaged up into a `.tar.gz` file. More detail on this follows later in this document.
1. Generate an SBoM.
1. Generate an OCI image tar file from the single layer `.tar.gz` file in [`oci.BuildImageTarballFromLayer()`](../pkg/build/oci/oci.go#L285).

## Layer Build

As described above, after everything is setup, the actual build occurs inside the working directory.
The build is in [`build.Context.BuildLayer()`](../pkg/build/build.go#L80-109), which consists of:

1. `Context.BuildImage()`: building the image
1. `Context.runAssertions()`: running assertions to validate that the build was successful
1. `Context.BuildTarball()`: build the tarball for the layer
1. `Context.GenerateSBOM()` optionally generate the SBoM

The actual building of the image via `BuildImage()` just wraps [`buildImage()`](../pkg/build/build_implementation.go#L195-247).

It involves several steps:

1. Validate the image configuration. This includes setting defaults.
1. Initialize the apk. This involves setting up the various apk directories inside the working directory.
1. Add additional tags for apk packages.
1. `MutateAccounts()`: Create users and groups.
1. Set file and directory permissions.
1. Set the symlinks for busybox, as busybox is a single binary which determines what action to take based on the invoked path.
1. Update ldconfig.
1. Create the `/etc/os-release` file.
1. If s6 is used for supervision, install it and create its configuration files.

Note that all of the steps involve some file manipulation.

* In the case of simply laying out files or changing permissions, this is straightforward and performed in the working directory.
* In the case of apk commands, it uses the [pkg/apk/impl](../pkg/apk/impl/) implementation to lay out files directly.
* In the case of `chown`/`chmod`, if it cannot do so directly - either because the underlying filesystem does not support it or because it is not running as root - it ignores the errors and keeps track of the intended ownership and permissions, adding them to the final layer tar stream.
* In the case of `ldconfig`, it replicates the equivalent functionality by parsing the library ELF headers and creating the symlinks.
* In the case of `busybox`, it creates symlinks to the busybox binary, based on a fixed list.
* In the case of character devices, if it cannot do so directly - either because the underlying filesystem does not support it or because it is not running as root - it ignores the errors and keeps track of the intended files, adding them to the final layer tar stream.

## Managing apk

All of the apk functions inside `apko` are performed by executing `apk` inside the chroot/proot jail.
They are abstracted via the `type apk.APK struct`, in order to simplify both testing and future changes.
For now, however, these simply execute `apk` commands.

In the future, this is likely to change to direct layout of files on disk and manipulation of the database.