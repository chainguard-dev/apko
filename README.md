# apko

Build images for apk-based distributions declaratively!

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

You need root, or at least fakeroot + fakechroot to build images
with apko, due to apk-tools' use of chroot(2).
