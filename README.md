# apko: apk-based OCI image builder

Build and publish [OCI container images](https://opencontainers.org/) built from [apk](https://wiki.alpinelinux.org/wiki/Package_management) packages.

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

You can install apko from Homebrew:

```shell
brew install apko
```

You can also install apko from source:

```shell
go install chainguard.dev/apko@latest
```

You can also use the apko container image:

```shell
docker run cgr.dev/chainguard/apko version
```

To use the examples, you'll generally want to mount your current directory into the container, e.g.:

```shell
docker run -v "$PWD":/work cgr.dev/chainguard/apko build examples/alpine-base.yaml apko-alpine:edge apko-alpine.tar
```

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

```shell
apko build examples/alpine-base.yaml apko-alpine:test apko-alpine.tar
```
```
...
2022/04/08 13:22:31 apko (aarch64): generating SBOM
2022/04/08 13:22:31 building OCI image from layer '/tmp/apko-3027985148.tar.gz'
2022/04/08 13:22:31 OCI layer digest: sha256:ba034c07d0945abf6caa46fe05268d2375e4209e169ff7fdd34d40cf4e5f2dd6
2022/04/08 13:22:31 OCI layer diffID: sha256:9b4ab6bb8831352b25c4bd21ee8259d1f3b2776deec573733291d71a390157bb
2022/04/08 13:22:31 output OCI image file to apko-alpine.tar
```

or, with Docker:

```shell
docker run -v "$PWD":/work cgr.dev/chainguard/apko build examples/alpine-base.yaml apko-alpine:test apko-alpine.tar
```

You can then load the generated tar image into a Docker environment:

```shell
docker load < apko-alpine.tar
```
```shell
Loaded image: apko-alpine:test
```
```shell
docker run -it apko-alpine:test
```
```
e289dc84c4ad:/# echo boo!
boo!
```

You can also publish the image directly to a registry:

```shell
apko publish examples/alpine-base.yaml myrepo/alpine-apko:test
```

See the [docs](./docs/apko_file.md) for details of the file format and the [examples directory](./examples) for more, err, examples!

## Debugging apko Builds

To include debug-level information on apko builds, add `--debug` to your build command:

```shell
docker run --rm -v ${PWD}:/work cgr.dev/chainguard/apko build --debug \
  apko.yaml hello-minicli:test hello-minicli.tar \
  -k melange.rsa.pub
```

## Why

apko was created by [Chainguard](https://www.chainguard.dev), who requires secure and reproducible
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

## Support and Further Reading

Tutorials and guides for apko can be found at the [Chainguard Academy](https://edu.chainguard.dev/open-source/apko/).

For support, please find us on the [Kubernetes Slack](https://kubernetes.slack.com/) in the #apko
channel or [open an issue](https://github.com/chainguard-dev/apko/issue).
 
## Related Work and Resources

The [melange project](https://github.com/chainguard-dev/melange) is designed to produce apk packages to be used in apko.

The [ko](https://github.com/google/ko) project builds Go projects from source in a similar manner to apko.

The [kontain.me](https://github.com/imjasonh/kontain.me) service creates fresh container images on
demand using different forms of declarative configuration (including ko and apko).


