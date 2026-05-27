# EROFS Output Format (experimental)

apko can emit image layers as [EROFS](https://erofs.docs.kernel.org/) filesystem images instead of the default gzip-compressed tar.
The format tracks the draft [erofs/erofs-image-spec](https://github.com/erofs/erofs-image-spec) (PR [#1](https://github.com/erofs/erofs-image-spec/pull/1)).
Until the spec reaches a stable release, the media types, annotations, and layer layout used here may change.

## Why EROFS?

- **Mount, don't unpack.** A layer blob is a complete, kernel-mountable read-only filesystem.
  You can `mount -t erofs` the layer directly and look at it, without extracting a tarball.
- **Random access.** Container runtimes that consume EROFS images can seek into a layer rather than streaming the whole tar.
- **Designed for sharing.** The spec defines `overlay-lower` and `overlay-data` roles that compose via the kernel's `overlayfs` exactly the way OCI tar layers do.

This document focuses on producing EROFS images and verifying they look legit using widely available tools.

## Prerequisites

To build and inspect EROFS images you need:

- apko built from a revision that contains EROFS support.
- The `erofs-utils` package, which provides `mkfs.erofs`, `fsck.erofs`, and `dump.erofs`.
  apko ships a pure-Go writer (no CGO), so `mkfs.erofs` is not required for *producing* images — but `fsck.erofs` and `dump.erofs` are the easiest way to inspect what apko produced.
- To mount an EROFS layer: either the kernel `erofs` module (present in modern Linux distros) plus root for `mount(8)`, or the unprivileged `erofsfuse` binary from `erofs-utils-fuse`.

Install on Wolfi / Chainguard / Alpine:

```sh
sudo apk add erofs-utils         # fsck.erofs, dump.erofs, mkfs.erofs
sudo apk add erofs-utils-fuse    # erofsfuse (optional, for unprivileged mount)
```

Install on Debian / Ubuntu:

```sh
sudo apt install erofs-utils erofsfuse
```

## Single-layer build

The simplest case: opt into EROFS via the `--format=erofs` flag or `format: erofs` in apko.yaml.

`erofs-demo.yaml`:

```yaml
contents:
  keyring:
    - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
  repositories:
    - https://packages.wolfi.dev/os
  packages:
    - wolfi-base

cmd: /bin/sh -l
archs:
  - host
```

Build into an OCI image layout directory:

```sh
mkdir -p out
apko build erofs-demo.yaml apko-erofs-demo:latest out/ --format=erofs --arch=$(uname -m)
```

The OCI layout under `out/` is a regular OCI image directory — the layer blob just happens to be an EROFS filesystem:

```
out/
├── blobs/sha256/
│   ├── <config-digest>       # JSON image config
│   ├── <manifest-digest>     # JSON image manifest
│   └── <layer-digest>        # raw EROFS filesystem image
├── index.json
└── oci-layout
```

### Verify the manifest references EROFS

```sh
MANIFEST=$(jq -r '.manifests[0].digest | split(":")[1]' out/index.json)
jq . out/blobs/sha256/$MANIFEST
```

Expected (excerpt):

```json
{
  "layers": [
    {
      "mediaType": "application/vnd.erofs",
      "size": 16207872,
      "digest": "sha256:8a2205cc..."
    }
  ]
}
```

The image config records `erofs` in `os.features` per spec §5.4, signalling to tools that don't implement the spec that they should not attempt to apply the layer as a tar:

```sh
CONFIG=$(jq -r '.config.digest | split(":")[1]' out/blobs/sha256/$MANIFEST)
jq '.["os.features"]' out/blobs/sha256/$CONFIG
# → ["erofs"]
```

## Inspect the layer (no mount required)

The layer blob is a complete EROFS filesystem. You can validate and inspect it without mounting anything.

### Identify the file

```sh
LAYER=$(jq -r '.layers[0].digest | split(":")[1]' out/blobs/sha256/$MANIFEST)
file out/blobs/sha256/$LAYER
# → out/blobs/sha256/...: EROFS filesystem, blocksize=12, exslots=0, ...
```

### Integrity check

```sh
fsck.erofs -d3 out/blobs/sha256/$LAYER
# <I> erofs: No errors found
```

### Dump the superblock

```sh
dump.erofs out/blobs/sha256/$LAYER | head -15
```

This prints the on-disk metadata: block size, inode count, build time, UUID, feature flags.

### Extract without root

`fsck.erofs --extract` reads every inode and writes the resulting tree to a directory.
This is the strongest unprivileged validation you can run: if the image is malformed, extraction fails; if it succeeds, the file tree on disk is exactly what a kernel mount would expose.

```sh
mkdir extracted
fsck.erofs --extract=extracted --xattrs --force out/blobs/sha256/$LAYER
ls extracted/
# bin  dev  etc  home  lib  ...
cat extracted/etc/os-release
```

### List contents with `apko erofs ls`

For a quick `tar tvf`-style listing of any EROFS source (raw blob or OCI image directory), use `apko erofs ls`. It opens the EROFS blobs directly, walks the merged view in user space, and prints one line per entry — no mounts, no root or FUSE required, works on Linux/macOS/Windows.

```sh
apko erofs ls out/blobs/sha256/$LAYER | head
# lrwxrwxrwx  0/0    7    2026-04-17 19:17  bin -> usr/bin
# drwxr-xr-x  0/0    115  2026-04-17 19:17  dev
# ...

apko erofs ls out/      # works against the whole OCI image too
```

For multi-layer images, `ls` applies AUFS-style overlay semantics in user space (whiteouts, opaque markers) to present the merged view the kernel would assemble.

## Mount the layer

`apko erofs mount SOURCE DEST` mounts a raw EROFS blob or an OCI image directory at `DEST`. It chooses between a kernel mount (root) and `erofsfuse` (unprivileged) based on the effective UID; use `--mode=kernel|fuse|auto` to force a choice. `apko erofs umount DEST` tears it back down.

```sh
mkdir -p /mnt/apko-erofs
apko erofs mount out/blobs/sha256/$LAYER /mnt/apko-erofs
ls /mnt/apko-erofs/
file /mnt/apko-erofs/bin/sh
apko erofs umount /mnt/apko-erofs
```

If the kernel mount mode complains "unknown filesystem type 'erofs'", the kernel module is missing on your system; install it (e.g. `linux-modules-extra-$(uname -r)` on Ubuntu) or pass `--mode=fuse` to use `erofsfuse`, which does not require root and works inside CI containers that lack the kernel module.

### Doing it manually

For reference, `apko erofs mount` is equivalent to one of:

```sh
# Kernel (root):
sudo mount -t erofs -o loop out/blobs/sha256/$LAYER /mnt/apko-erofs
# ...later:
sudo umount /mnt/apko-erofs

# FUSE (unprivileged):
erofsfuse out/blobs/sha256/$LAYER /mnt/apko-erofs
# ...later:
fusermount3 -u /mnt/apko-erofs       # or `fusermount -u`
```

## Pulling from a registry

If you push the image with `apko publish` or `crane push`, the registry stores each blob unchanged — including the EROFS layer blob.
Most registry clients can extract layers by digest:

```sh
# Read the manifest and pull layer blobs.
crane manifest registry.example.com/apko-erofs-demo:latest > manifest.json
LAYER_DIGEST=$(jq -r '.layers[0].digest' manifest.json)
crane blob registry.example.com/apko-erofs-demo:latest@$LAYER_DIGEST > layer.erofs

file layer.erofs           # EROFS filesystem...
fsck.erofs -d3 layer.erofs # <I> erofs: No errors found
```

Once you have the blob on disk you can inspect or mount it exactly as in the previous sections.

## Multi-layer builds

Combine `format: erofs` with apko's [layering](layering.md) configuration to get one EROFS layer per package group plus a top layer for unowned files.

`erofs-layered.yaml`:

```yaml
contents:
  keyring:
    - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
  repositories:
    - https://packages.wolfi.dev/os
  packages:
    - wolfi-base

cmd: /bin/sh -l
archs:
  - host

layering:
  strategy: origin
  budget: 4

format: erofs
```

```sh
mkdir -p out-layered
apko build erofs-layered.yaml apko-erofs-layered:latest out-layered/ --arch=$(uname -m)
```

Inspect the manifest:

```sh
MANIFEST=$(jq -r '.manifests[0].digest | split(":")[1]' out-layered/index.json)
jq '.layers[] | {mediaType, role: .annotations["org.erofs.role"]}' out-layered/blobs/sha256/$MANIFEST
```

Expected (last layer carries no role per spec §3.8 rule 1):

```json
{ "mediaType": "application/vnd.erofs", "role": "overlay-lower" }
{ "mediaType": "application/vnd.erofs", "role": "overlay-lower" }
{ "mediaType": "application/vnd.erofs", "role": "overlay-lower" }
{ "mediaType": "application/vnd.erofs", "role": "overlay-lower" }
{ "mediaType": "application/vnd.erofs", "role": null }
```

Each layer is independently mountable as an EROFS filesystem, and each carries its own partial `usr/lib/apk/db/installed` so per-layer scanners (Trivy, Snyk, Grype) can identify the packages it contributes.

### Assemble the full rootfs with overlayfs

The OCI spec composes layers with `overlayfs`-style semantics; for EROFS layers the composition is straightforward.
The simplest way is `apko erofs mount`, which mounts each layer and assembles the overlay in one step:

```sh
mkdir -p mnt
apko erofs mount out-layered/ mnt/
ls mnt/merged/                     # full rootfs
cat mnt/.apko-erofs-mount.json     # records the mounts for teardown
apko erofs umount mnt/             # unwinds the overlay and every layer
```

The directory layout produced under `DEST` is:

```
mnt/
├── layers/00..NN              # one EROFS mountpoint per layer (00 is base)
├── upper/                     # overlayfs upperdir
├── work/                      # overlayfs workdir
├── merged/                    # combined view
└── .apko-erofs-mount.json     # state file consumed by `apko erofs umount`
```

`apko erofs mount` picks kernel mounts when running as root and falls back to `erofsfuse` + (kernel overlay over FUSE, then `fuse-overlayfs`) otherwise. Force one path with `--mode=kernel|fuse|auto`.

#### Doing it manually

For reference, the equivalent without `apko erofs mount`:

```sh
# Pull each layer blob out of the OCI layout.
ROOT=$(pwd)/out-layered/blobs/sha256
mkdir -p mnt/{lower0,lower1,lower2,lower3,top,merged,work,upper}

LAYERS=$(jq -r '.layers[].digest | split(":")[1]' $ROOT/../../blobs/sha256/$MANIFEST)
i=0
for d in $LAYERS; do
  sudo mount -t erofs -o loop "$ROOT/$d" "mnt/lower$i" 2>/dev/null || \
    erofsfuse "$ROOT/$d" "mnt/lower$i"
  i=$((i+1))
done

# In overlayfs, lowerdirs are listed top-down (highest priority first).
# OCI orders layers bottom-up (index 0 is the base), so reverse the order.
sudo mount -t overlay overlay \
  -o lowerdir=mnt/lower$((i-1)):mnt/lower$((i-2)):mnt/lower1:mnt/lower0,upperdir=mnt/upper,workdir=mnt/work \
  mnt/merged

ls mnt/merged/   # full rootfs
```

Clean up:

```sh
sudo umount mnt/merged
for d in mnt/lower*; do sudo umount "$d" 2>/dev/null || fusermount -u "$d"; done
```

Production runtimes (containerd's erofs snapshotter, podman/CRI-O with the erofs-aware plugin, etc.) automate this assembly; both `apko erofs mount` and the manual steps above are for verifying that an apko-built EROFS image really does compose into a valid rootfs.

## Current limitations

- **No compression.** apko emits raw `application/vnd.erofs` layers only. The draft spec defines `application/vnd.erofs+zstd` but neither apko's writer nor the underlying go-erofs library writes compressed images yet.
- **No dm-verity.** The spec's verified-mount path (§3.5) is not produced.
- **No chunk index.** Lazy-loading runtimes (per spec §3.4) won't get an index; reads are sequential.
- **No `overlay-data` or `device` roles.** Only `overlay-lower` (and unannotated final) layers are emitted.
- **Spec is draft.** Media-type strings and annotation keys may change before the spec stabilizes. Treat any image built today as experimental.

If you need any of the above, please open an issue.

## See also

- [erofs/erofs-image-spec PR #1](https://github.com/erofs/erofs-image-spec/pull/1) — the layer format spec apko tracks.
- [EROFS kernel documentation](https://erofs.docs.kernel.org/) — on-disk format reference.
- [Layering in apko](layering.md) — how the multi-layer strategy partitions packages into groups.
