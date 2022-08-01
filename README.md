# apko: APK-based OCI image builder

Build and publish [OCI container images](https://opencontainers.org/) built from [APK](https://wiki.alpinelinux.org/wiki/Package_management) packages.

apko has the following key features:

 - **Fully reproducible by default.** Run apko twice and you will get exactly the same binary.
 - **Fast.** apko aims to build images in ms.
 - **Small.** apko generated images only contain what's needed by the application,
   in the style of [distroless](https://github.com/GoogleContainerTools/distroless).
 - **SBOM Support.** apko produces a Software Bill of Materials (SBOM) for images, detailing all the packages inside.
 - **Services.** apko supports using the [s6 supervision suite](https://skarnet.org/software/s6) to run multiple processes
   in a container without reaping or signalling issues.

Please note that apko is a work in progress and details are subject to change!

## Installation

apko has a dependency on [apk-tools](https://gitlab.alpinelinux.org/alpine/apk-tools). If you're not running on Alpine Linux or another apk-based distribution, the quickest way to get apko running is to use the OCI Container (Docker) image:

```
$ docker run distroless.dev/apko version
     _      ____    _  __   ___
    / \    |  _ \  | |/ /  / _ \
   / _ \   | |_) | | ' /  | | | |
  / ___ \  |  __/  | . \  | |_| |
 /_/   \_\ |_|     |_|\_\  \___/
apko

GitVersion:    v0.5.0-20-g8cbefb9
GitCommit:     8cbefb9bda9136e540193cc036067d9c3662b277
GitTreeState:  clean
BuildDate:     2022-07-27T21:11:55
GoVersion:     go1.18.4
Compiler:      gc
Platform:      linux/arm64
```

To use the examples, you'll generally want to mount your current directory into the container e.g:

```
$ docker run -v "$PWD":/work distroless.dev/apko build examples/alpine-base.yaml apko-alpine:edge apko-alpine.tar
...
```

The above examples use [Docker](https://docs.docker.com/get-docker/), but should also work with other runtimes such as [podman](https://podman.io/getting-started/installation).

Alternatively, if you're on a Mac, you can use [Lima](./mac/README.md) to run an Alpine Linux VM.

## Quickstart

An apko file for building an Alpine base image looks like this:

```yaml
contents:
  repositories:
    - https://dl-cdn.alpinelinux.org/alpine/edge/main
  packages:
    - alpine-base

entrypoint:
  command: /bin/sh -l

# optional environment configuration
environment:
  PATH: /usr/sbin:/sbin:/usr/bin:/bin
```
We can build this with apko from any environment with apk tooling:

```
$ apko build examples/alpine-base.yaml apko-alpine:test apko-alpine.tar
...
2022/04/08 13:22:31 apko (aarch64): generating SBOM
2022/04/08 13:22:31 building OCI image from layer '/tmp/apko-3027985148.tar.gz'
2022/04/08 13:22:31 OCI layer digest: sha256:ba034c07d0945abf6caa46fe05268d2375e4209e169ff7fdd34d40cf4e5f2dd6
2022/04/08 13:22:31 OCI layer diffID: sha256:9b4ab6bb8831352b25c4bd21ee8259d1f3b2776deec573733291d71a390157bb
2022/04/08 13:22:31 output OCI image file to apko-alpine.tar
```

And load it into a Docker environment:

```
$ docker load < apko-alpine.tar
Loaded image: apko-alpine:test
$ docker run -it apko-alpine:test
e289dc84c4ad:/# echo boo!
boo!
```

Or publish the image directly to a registry.

```
$ apko publish examples/alpine-base.yaml myrepo/alpine-apko:test
...
```

See the [docs](./docs/apko_file.md) for details of the file format and the [examples
directory](./examples) for more, err, examples!


## Why

apko was created by [Chainguard](https://www.chainguard.dev), who require secure and reproducible
container images for their tooling. Speed is also a critical factor; Chainguard require images to be
rebuilt constantly in response to new versions and patches.

The design of apko is heavily influenced by the [ko](https://github.com/google/ko) and
[distroless](https://github.com/GoogleContainerTools/distroless) projects. 

## Declarative Nature

By design, apko doesn't support an equivalent of `RUN` statements in Dockerfiles. This means apko
files are fully declarative and allows apko to make stronger statements about the contents of images.
In particular, apko images are fully bitwise reproducible and can generate SBOMs covering their
complete contents.

In order to install bespoke tooling or applications into an image, they must first be packaged into
an apk. This can be done with apko's sister tool [melange](https://github.com/chainguard-dev/melange).

The combination of melange and apko cover the vast majority of use cases when building container
images. In the cases where they are not a good fit, our recommendation is to build a base image with
apko and melange, then use traditional tooling such as Dockerfiles for the final step.

## Related work and resources

The [melange project](https://github.com/chainguard-dev/melange) is designed to produce apk packages to be used in apko.

The [ko](https://github.com/google/ko) project builds Go projects from source in a similar manner to apko.

The [kontain.me](https://github.com/imjasonh/kontain.me) service creates fresh container images on
demand using different forms of declarative configuration (including ko and apko).
