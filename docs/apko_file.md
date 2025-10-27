# The apko File Format

Apko files are a YAML based declarative definition of an image to be built by apko. Unlike
Dockerfiles, there is no support for running arbitrary Unix commands (i.e. there is no equivalent of
`RUN` statements). This means apko can guarantee the contents and reproducibility of the final
image, as well as produce extra metadata such as SBOMs.

## Simple Example

This is easier to understand by looking at a simple example:

```yaml
contents:
  repositories:
    - https://dl-cdn.alpinelinux.org/alpine/v3.22/main
  packages:
    - alpine-base

entrypoint:
  command: /bin/sh -l

# optional environment configuration
environment:
  PATH: /usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
```

Running `apko build` on this file will produce a tar file containing an Alpine base container image.
The image can be used by container runtimes (for example, running  `docker load image.tar` will add
the image to Docker). The command `apko publish` can also be used to directly push the image to an
image registry.

The file contents of the image are completely specified in the `contents` section. In this case, a
single [Alpine package](https://pkgs.alpinelinux.org/packages) or apk called "alpine-base" is
installed. This apk includes only the minimal set of files needed for a working Alpine linux image.
The rest of the file specifies various metadata, including the default command to run and
environment variables to set.

## Complete Example

The following example builds an nginx image and covers the full range of apko features:

```yaml
contents:
  repositories:
    - https://dl-cdn.alpinelinux.org/alpine/v3.22/main
  packages:
    - alpine-baselayout
    - nginx

entrypoint:
  type: service-bundle
  services:
    nginx: /usr/sbin/nginx -c /etc/nginx/nginx.conf -g "daemon off;"

stop-signal: SIGQUIT

work-dir: /usr/share/nginx

accounts:
  groups:
    - groupname: nginx
      gid: 10000
  users:
    - username: nginx
      uid: 10000
      shell: /bin/sh
  run-as: nginx

# optional environment configuration
environment:
  PATH: /usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin

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

annotations:
  foo: bar
  bar: baz

# optional layering strategy
layering:
  strategy: origin
  budget: 10
```

Details of each field can be found below.

## Reference

### Contents top level element

`contents` defines the file contents of the image. This is the primary way of adding files to an image.

There are multiple possible child elements:

 - `repositories` defines a list of alpine repositories to look in for packages. These can be either
   URLs or file paths. File paths should start with a label like `@local` e.g: `@local /github/workspace/packages`.
   Notice that you need to package name under `packages` with the label e.g `- alpine-baselayout@local`.
 - `packages` defines a list of alpine packages to install inside the image
 - `keyring` PGP keys to add to the keyring for verifying packages.

### Entrypoint top level element

`entrypoint` defines the default commands and/or services to be executed by the container at runtime.

There are several child elements:

 - `type`: if this is set to `service-bundle`, the s6 supervisor will be used to start commands
   listed in `services`
 - `command`: if the type is not `service-bundle`, this can be set to specify a command to run when the
   container starts. Note that this sets the "entrypoint" value on OCI images (contrast with the
   `cmd` top level element).
 - `shell-fragment`: if the type is not `service-bundle`, this behaves like `command`, except that the
   command is a shell fragment.
 - `services`: a map of service names to commands to run by the s6 supervisor. `type` should be set
   to `service-bundle` when specifying services.

Services are monitored with the [s6 supervisor](https://skarnet.org/software/s6/index.html).

### Cmd top level element

`cmd` defines a command to run when the container starts up. If `entrypoint.command` is not set, it
will be executed with `/bin/sh -c`. If `entrypoint.command` is set, `cmd` will be passed as arguments to
`entrypoint.command`. This sets the "cmd" value on OCI images.

### Stop-Signal top level element

`stop-signal` configures the shutdown signal sent to the main process in the container by the
runtime. By default this is SIGTERM. Be careful when using this alongside a `service-bundle`
entrypoint which will intercept and potentially reinterpret the signal.

### Work-dir top level element

Sets the working directory for the image. Entrypoint and Cmd commands are taken as relative to
this path. This is useful for setting a default directory for input/output and for images that are
subsequently used in Dockerfiles.

Equivalent to [WORKDIR](https://docs.docker.com/engine/reference/builder/#workdir) in Dockerfile
syntax.

### Accounts top level element

`accounts` is used to set-up user accounts in the image and can be used when running processes in
the container. It is best practice to set an account to avoid processes running as root which can be
a security issue.

There are several child elements:

 - `users`: list of users and associated uids to include in the image e.g:
```yaml
  users:
    - username: nginx
      uid: 10000
      shell: /bin/sh
```
 - `run-as`: name of the user to run the main process under (should match a username or uid specified in
   users)
 - `groups`: list of group names and associated gids to include in the image e.g:

```yaml
  groups:
    - groupname: nginx
      gid: 10000
```

### Archs top level element

`archs` defines a list architectures to build the image for. Valid values are: `386`, `amd64`, `arm64`, `arm/v6`, `arm/v7`,
`ppc64le`, `riscv64`, `s390x`.

### Environment

`environment` defines a list of environment variables to set within the image e.g:

```yaml
environment:
    FOO: bar
```

will set the environment variable named "FOO" to the value "bar".


### Paths

`paths` defines filesystem operations that can be applied to the image. This includes
setting permissions on files or directories as well as creating empty files, directories and links.

The `paths` element contains the following children:

 - `path`: filesystem path to manipulate
 - `type`: The type of file operation to perform. This can be:
   - `directory`: create an empty directory at the path
   - `empty-file`: create an empty file at the path
   - `hardlink`: create a hardlink (`ln`) at the path, linking to the value specified in `source`
   - `symlink`: create a symbolic link (`ln -s`) at the path, linking to the value specified in
     `source`
   - `permissions`: sets file permissions on the file or directory at the path.
 - `uid`: UID to associate with the file
 - `gid`: GID to associate with the file
 - `permissions`: file permissions to set. Permissions should be specified in octal e.g. 0o755 (see `man chmod` for details).
 - `source`: used in `hardlink` and `symlink`, this represents the path to link to.


### Includes

`include` defines a path to a configuration file which should be used as the base configuration,
the configuration data is layered on top of this base configuration.  By default, there is no
base configuration used.

The path can be either a local file, or a file in a remote git repository, in the same style as
Go package names and Github Actions.  For example, the following include line would reference
`examples/alpine-base.yaml` in the apko git repository:

```
include: github.com/chainguard-dev/apko/examples/alpine-base.yaml@main
```

At present, the path structure assumes that the git repository lives on a site similar to
GitHub, GitLab or Gitea.  In other words, given an include path like the above, it will
parse as:

```
host: github.com
repository: chainguard-dev/apko
path: examples/alpine-base.yaml
reference: main
```

Patches to improve the parsing to make it more flexible are welcome.

### Annotations

`annotations` defines the set of annotations that should be applied to images and indexes.

### Layering

`layering` defines a strategy for splitting the filesystem contents into layers.

It contains the following children:

 - `strategy`: The strategy to employ (currently, only "origin" is valid).
 - `budget`: The number of additional layers apko will use for layering.

See [layering.md](layering.md) for more information.
