# EROFS Output Format (experimental)

apko can emit image layers as [EROFS](https://erofs.docs.kernel.org/) filesystem images instead of the default gzip-compressed tar.
The format tracks [erofs/erofs-image-spec](https://github.com/erofs/erofs-image-spec); section numbers below refer to [`spec.md`](https://github.com/erofs/erofs-image-spec/blob/main/spec.md) on `main`.
The spec is still in its draft phase — there is no tagged release, and it says media-type strings, annotation keys, and the binary chunk-index layout are subject to change until the first stable one.
So the media types, annotations, and layer layout used here may change too.

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
sudo apt install erofs-utils    # ships mkfs.erofs, fsck.erofs, dump.erofs, and erofsfuse
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
apko build erofs-demo.yaml apko-erofs-demo:latest out/ --format=erofs --arch=host
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
fsck.erofs --extract=extracted --force out/blobs/sha256/$LAYER
ls extracted/
# bin  dev  etc  home  lib  ...
cat extracted/etc/os-release
```

Flag availability varies between erofs-utils releases — `--xattrs`, for instance, is not in the version Debian and Ubuntu ship — so check `fsck.erofs --help` on your machine before reaching for anything beyond the above.

### List contents with `apko erofs ls`

For a quick `tar tvf`-style listing of any EROFS source (raw blob or OCI image directory), use `apko erofs ls`. It opens the EROFS blobs directly, walks the merged view in user space, and prints one line per entry — no mounts, no root or FUSE required, works on Linux/macOS/Windows.

Each line is mode, uid/gid, size, mtime and path; setuid/setgid/sticky show up in the mode string as `ls -l` renders them, devices print `major,minor` in place of a size, and directories print 0 as they do in `tar tv`.

```sh
apko erofs ls out/blobs/sha256/$LAYER | head
# lrwxrwxrwx  0/0     7       2026-04-17 19:17  bin -> usr/bin
# drwxr-xr-x  0/0     0       2026-04-17 19:17  dev
# crw-rw-rw-  0/0     1,3     2026-04-17 19:17  dev/null
# drwxrwxrwt  0/0     0       2026-04-17 19:17  tmp
# -rwsr-xr-x  0/0     178528  2026-04-17 19:17  usr/bin/sudo
# -rw-r--r--  13/15   1183    2026-04-17 19:17  usr/share/man/whatis
# ...

apko erofs ls out/      # works against the whole OCI image too
```

For multi-layer images, `ls` applies overlay semantics in user space. It uses the overlayfs-native deletion encoding the spec mandates (§3.6) — a whiteout is a character device with rdev 0, an opaque directory sets `trusted.overlay.opaque="y"` — not the `.wh.` filename convention of tar layers, which §8.1 forbids in EROFS images. A single-layer image is listed as-is: the kernel would mount it directly, applying no overlay semantics, so neither does `ls`.

The merge approximates what the kernel would assemble, and diverges in two corners (see [#2408](https://github.com/chainguard-dev/apko/issues/2408)), both of which need two or more layers:

- A whiteout — or a plain file — at a directory's own name in a middle layer does not cut off lower layers when a higher layer recreates that directory. `ls` shows the union of the recreated directory and the layers below the whiteout; the kernel shows only the recreated directory.
- Opacity is not inherited by descendant directories. Marking `a` opaque hides lower layers' children of `a`, but not lower layers' children of `a/b`; the kernel's cut covers the whole subtree.

## Mount the layer

`apko erofs mount SOURCE DEST` mounts a raw EROFS blob or an OCI image directory at `DEST`. It chooses between a kernel mount (root) and `erofsfuse` (unprivileged) based on the effective UID; use `--mode=kernel|fuse|auto` to force a choice. `apko erofs umount DEST` tears it back down.

The mount is **read-only** unless you pass `--rw`. Read-only is what inspecting an image wants, and it lets a single-layer image skip overlayfs entirely — the lone layer is mounted straight at `DEST/merged`. With `--rw` you get an overlayfs upperdir at `DEST/upper`; `umount` removes it only if nothing was written through the mount, and otherwise leaves it where it is and logs the path. A later `--rw` mount at the same `DEST` then refuses to start until you move or remove it, rather than quietly stacking two sessions' writes — possibly from different images — on top of each other.

```sh
mkdir -p /mnt/apko-erofs
apko erofs mount out/blobs/sha256/$LAYER /mnt/apko-erofs
ls /mnt/apko-erofs/
file /mnt/apko-erofs/bin/sh
apko erofs umount /mnt/apko-erofs
```

If the kernel mount mode complains "unknown filesystem type 'erofs'", the kernel module is missing on your system; install it (e.g. `linux-modules-extra-$(uname -r)` on Ubuntu) or pass `--mode=fuse` to use `erofsfuse`, which does not require root and works inside CI containers that lack the kernel module.

For an OCI source, `umount` works from `DEST/.apko-erofs-mount.json`, which `mount` wrote; a raw blob has no enclosing directory to hold one, so `umount` falls back to unmounting `DEST` itself. It only accepts mountpoints that a mount creates under `DEST` — `DEST/merged` and `DEST/layers/NN` — so a tampered file cannot name a path outside `DEST`. Because that is a check on the path *string*, a symlink at `DEST/merged` would otherwise redirect it anyway; kernel mode unmounts with `umount(2)` and `UMOUNT_NOFOLLOW`, which refuses that in the same syscall, with no window. A symlinked *parent* (`DEST/layers` itself) is caught by a separate check, and there the check and the unmount are two steps — so **use a `DEST` only you can write to**: anywhere else, another user can race them and choose what your `umount` takes down.

If a mountpoint is busy, `umount` stops there and rewrites the state file to list only what is still mounted, so rerunning it once the mount is free finishes the teardown.

### Doing it manually

A layer blob is a complete filesystem image, so mounting it needs no apko-specific tooling. For reference, `apko erofs mount` is equivalent to one of:

```sh
# Kernel (root):
sudo mount -t erofs -o ro out/blobs/sha256/$LAYER /mnt/apko-erofs
# ...later:
sudo umount /mnt/apko-erofs

# FUSE (unprivileged):
erofsfuse out/blobs/sha256/$LAYER /mnt/apko-erofs
# ...later:
fusermount3 -u /mnt/apko-erofs       # or `fusermount -u`
```

`hack/test-erofs.sh` runs everything above in one go — build, `fsck.erofs`, kernel mount, a comparison of `apko erofs ls` against the mounted tree, and a round trip through `apko erofs mount` and `apko erofs umount` (read-only, `--rw`, a raw blob, and a tampered state file) — and is what the `EROFS` CI workflow executes.

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
apko build erofs-layered.yaml apko-erofs-layered:latest out-layered/ --arch=host
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

The OCI spec composes layers with `overlayfs`-style semantics; for EROFS layers the composition is straightforward — mount each layer read-only, then stack them as `lowerdir`s:

```sh
# Pull each layer blob out of the OCI layout.
BLOBS=$(pwd)/out-layered/blobs/sha256
MANIFEST=$(jq -r '.manifests[0].digest | split(":")[1]' out-layered/index.json)
mkdir -p mnt/{merged,work,upper}

# Mount every layer; build the overlay lowerdir as we go. overlayfs lists
# lowerdirs top-down (highest priority first), while OCI orders layers
# bottom-up (index 0 is the base), so prepend each new layer.
LOWERS=
i=0
for d in $(jq -r '.layers[].digest | split(":")[1]' "$BLOBS/$MANIFEST"); do
  mp=mnt/lower$(printf %02d $i)
  mkdir -p "$mp"
  sudo mount -t erofs -o ro "$BLOBS/$d" "$mp" 2>/dev/null || \
    erofsfuse "$BLOBS/$d" "$mp"
  LOWERS="$mp${LOWERS:+:$LOWERS}"
  i=$((i+1))
done

sudo mount -t overlay overlay \
  -o "lowerdir=$LOWERS,upperdir=mnt/upper,workdir=mnt/work" \
  mnt/merged

ls mnt/merged/   # full rootfs
```

Clean up:

```sh
sudo umount mnt/merged
for d in mnt/lower*; do sudo umount "$d" 2>/dev/null || fusermount -u "$d"; done
```

Production runtimes (containerd's erofs snapshotter, podman/CRI-O with the erofs-aware plugin, etc.) automate this assembly; the steps above are for verifying that an apko-built EROFS image really does compose into a valid rootfs.

## Using EROFS support as a Go library

### From apko-consuming projects

If you're already building apko images programmatically (`apko_build.New(ctx, fsys, opts...).BuildImage(...)`), EROFS is just a configuration choice — set the layer format on your `ImageConfiguration` and apko handles the rest:

```go
import (
    apko_build "chainguard.dev/apko/pkg/build"
    apko_types "chainguard.dev/apko/pkg/build/types"
)

imgConfig := apko_types.ImageConfiguration{
    // ... your existing fields ...
    Format: apko_types.LayerFormatErofs,
}

bc, err := apko_build.New(ctx, fsys, apko_build.WithImageConfiguration(imgConfig), ...)
if err != nil { /* ... */ }
if err := bc.BuildImage(ctx); err != nil { /* ... */ }
_, layer, err := bc.ImageLayoutToLayer(ctx)
```

### From projects that don't use apko

If you have a plain `fs.FS` and want an EROFS image, **use [go-erofs](https://github.com/erofs/go-erofs) directly** — apko doesn't expose its EROFS writer as a standalone library (and wrapping go-erofs wouldn't add meaningful value over its existing `Writer.CopyFrom(fs.FS)` API).

For inspection, apko *does* expose a focused leaf library — see `chainguard.dev/apko/pkg/erofsmount` — which provides `Stack` (layered `fs.FS` with overlay/whiteout semantics), `OpenLayers` (open an OCI EROFS image's blobs), `ReadOCILayers` (parse an OCI manifest with EROFS layers), and `Mount`/`Unmount`/`Ls` (the CLI subcommand helpers, Linux-only for mount/umount; `Ls` is cross-platform).

## Current limitations

- **No compression.** apko emits raw `application/vnd.erofs` layers only. The draft spec defines `application/vnd.erofs+zstd` but neither apko's writer nor the underlying go-erofs library writes compressed images yet.
- **No dm-verity.** The spec's verified-mount path (§3.5) is not produced.
- **No chunk index.** Lazy-loading runtimes (per spec §3.4) won't get an index; reads are sequential.
- **No `overlay-data` or `device` roles.** Only `overlay-lower` (and unannotated final) layers are emitted.
- **Hardlinks become independent copies.** apko's EROFS writer materializes each link as its own inode, so it costs another full copy of the file's data (rounded up to the block size) and `st_nlink`/`st_ino` identity is lost. Spec §3.7's materialize-or-fail rule covers *cross-layer* hardlinks; within a single layer the spec is silent, so this is conformant but not blessed by that section. Either way, a hardlink-heavy image will be larger as EROFS than as tar, where extra links are zero-byte entries.
- **Spec is draft.** Media-type strings and annotation keys may change before the spec stabilizes. Treat any image built today as experimental.

If you need any of the above, please open an issue.

## See also

- [erofs/erofs-image-spec `spec.md`](https://github.com/erofs/erofs-image-spec/blob/main/spec.md) — the layer format spec apko tracks.
- [EROFS kernel documentation](https://erofs.docs.kernel.org/) — on-disk format reference.
- [Layering in apko](layering.md) — how the multi-layer strategy partitions packages into groups.
