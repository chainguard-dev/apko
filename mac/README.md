# apko on mac

Currently `apko` relies on `apk`, which is currently
not available for mac.

This page documents workarounds to run
`apko` on a mac.

## OCI Container (Docker)

Use the [official container image](https://github.com/chainguard-images/apko):

```
$ docker run -v $PWD:/work cgr.dev/chainguard/apko build examples/alpine-base.yaml apko-alpine:edge apko-alpine.tar
```

## Lima

We maintain an example configuration file for
[Lima](https://github.com/lima-vm/lima)
(see [`lima/apko-playground.yaml`](./lima/apko-playground.yaml)).

This provides a VM with the following:

- 1 CPU, 2GiB memory, 10GiB disk
- Latest release of `apko` (from Alpine edge repo)
- Useful tools such as `vim`
- Latest releases of various Docker credential helpers (ECR, GCR)
- Dummy version of `docker-credential-osxkeychain`
- Example config files from the repo at `/examples`

Your `$HOME` directory will be mounted into the VM (read-only), in
order to have access to things such as `~/.docker/config.json`,
cloud registry credentials, etc.

Root shell is needed for `apko build`. We also override `$HOME` with
your mac's `$HOME` (mounted into the VM) so that Docker credential
helpers work properly with `apko publish`.

The commands below assume to be run in this
directory of the repository, and require `limactl`.

### Start environment

```
limactl start --tty=false lima/apko-playground.yaml
```

### Obtain a shell

```
limactl shell apko-playground sudo su -c "HOME=\"${HOME}\" ash"
```

### Build an example image

```
apko build /examples/nginx.yaml tag /tmp/output.tar
```

### Publish an example image

```
apko publish /examples/nginx.yaml <registry_ref>
```

### Delete environment

```
limactl delete -f apko-playground
```
