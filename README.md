# apko: APK-based OCI image builder

Build OCI images for apk-based distributions declaratively!

## Why

When maintaining images at scale, the `Dockerfile` concept built into
Docker is inefficient.  If we have a collection of build artifacts,
repositories and a keyring, we can build images directly with APK,
and upload them directly to container registries.

In fact, we can do more than that: using a service like [kontain.me][km],
we can serve fresh container images on demand, with the latest package
updates, using nothing but declarative configuration.

   [km]: https://github.com/imjasonh/kontain.me

## How

This part is very much a work in progress, but basically you need
a system with `apk` (soon: `libapk`), and this `apko` tool.  You
probably also want the other Chainguard stack components as well,
e.g. `crane`.

To build an image, use the `apko build` command:

    # apko build config.yaml tag output.tar

This will give you a Docker-style tarball which you can use with
`docker load`:

    # docker load < output.tar

You can also publish an image using the `apko publish` command:

    # apko publish config.yaml foo.dev/bar/baz:latest

You need root, or at least fakeroot + fakechroot to build images
with apko, due to apk-tools' use of chroot(2).

Some example configurations are available in the examples
directory.

Want to run `apko` on a mac? See [here](./mac/README.md).

## Features

### Sub-second image build times

By using the very fast apk package manager to manage build artifacts,
we can build images very quickly.  This means that developers win with
a faster and more easy to reproduce build process.

### Service bundles

Some containers are complex, with multiple tightly-coupled services
running in the same container.  `apko` understands this scenario out
of the box, avoiding the need to deal with things like `s6-overlay`.
If you define a `service-bundle` entrypoint, it will generate an
appropriate supervision tree and ensure `s6` is installed.

### SBOM (coming soon)

As a result of using apk to manage distribution and build artifacts,
we will be able to generate SBOMs for containers, using the new
apk-tools 3.x SBOM feature.
