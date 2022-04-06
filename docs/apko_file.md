# The apko File Format

Apko files are a YAML based declarative definition of an image to be built by apko. Unlike
Dockerfiles, there is no support for running arbitrary Unix commands (i.e. RUN statements), which
allows apko to guarantee the contents of the final image and produce extra metadata such as SBOMs.

## Simple Example

This is easier to understand by looking at a simple example:

```
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

Running `apko build` on this file will produce a tar file containing an Alpine base container image.
The image can be used by container runtimes (e.g. run `docker load image.tar` to add to Docker). The
command `apko publish` can also be used to directly push the image to an image registry.

The file contents of the image are completely specified in the `contents` section. In this case, a
single Alpine package (TK link) or apk is installed which TK. The rest of the file specifies various
metadata, including the default command to run and environment variables to set.

## Complete Example

The following example builds an nginx image and covers the full range of apko features:

```
contents:
  repositories:
    - https://dl-cdn.alpinelinux.org/alpine/edge/main
  packages:
    - alpine-baselayout
    - nginx

entrypoint:
  type: service-bundle
  services:
    nginx: /usr/sbin/nginx -c /etc/nginx/nginx.conf -g "daemon off;"

accounts:
  groups:
    - groupname: nginx
      gid: 10000
  users:
    - username: nginx
      uid: 10000
  run-as: nginx

# optional environment configuration
environment:
  PATH: /usr/sbin:/sbin:/usr/bin:/bin

# optional path mutations
paths:
  - path: /run/nginx
    type: directory
    uid: 10000
    gid: 10000
    permissions: 0o755
  - path: /etc/nginx/http.d/default.conf
    type: hardlink
    source: /usr/share/nginx/http-default_server.conf
    uid: 10000
    gid: 10000
    permissions: 0o644

archs:
 - amd64
 - 386

```

Details of each field can be found below.

## Reference

### Contents top level element

`contents` defines the file contents of the image. The primary way of adding files to an image

There are multiple possible child elements:

 - `repositories` defines a list of alpine repositories to look in for packages (TK can these be
   files as well as URLs?)
 - `packages` defines a list of alpine packages to install inside the image
 - `keyring` TK

### Entrypoint top level element

`entrypoint` defines the default commands and/or services to be executed by the container at runtime. It is directly
analogous to TK.

There are several child elements:

 - `type`: if this is set to `service-bundle`, the s6 supervisor will be used to start commands
   listed in `services`
 - `cmd`: if the type is not `service-bundle`, this can be set to specify a command to run when the
   container starts. TK is this the equivalent of entrypoint or cmd?
 - `services`: a map of service names to commands to run by the s6 supervisor. `type` should be set
   to `service-bundle` when specifying services.

Services are monitored with the [s6 supervisor](https://skarnet.org/software/s6/index.html).

### Accounts


run-as
users, UID, UserName, GID
groups


### Archs top level element

`archs` defines a list architectures to build an image for. Valid values are 386, amd64, arm64, arm/v6, arm/v7,
ppc64le, riscv64, s390x. TK what about armv7, x86_64, aarch64, armhf?

TK does this produce a "fat manifest"? Does it load in Docker?

### Environment

`environment` defines a list of environment variables to set within the image e.g: 

```
environment:
    FOO: bar
```

will set the environment variable named "FOO" to the value "bar".


### Paths

TK


