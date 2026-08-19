#!/usr/bin/env bash

# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

# End-to-end check of an apko --format=erofs build: the layer blob is a real
# EROFS filesystem that erofs-utils accepts and the kernel will mount, and
# `apko erofs ls` reports the same tree the kernel does.
#
# Usage: hack/test-erofs.sh <yaml>
#
# Example:
#   hack/test-erofs.sh ./examples/wolfi-base.yaml
#
# Requires: jq, erofs-utils (fsck.erofs, dump.erofs), the kernel erofs driver,
# and root (or passwordless sudo) for the mount.  Set APKO to use a binary
# other than ./apko.

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <yaml>"
    exit 1
fi

yaml="$1"
apko="${APKO:-./apko}"
name=$(basename "${yaml}" .yaml)

if [ ! -x "${apko}" ]; then
    echo "no apko binary at ${apko}; run 'make apko' first" >&2
    exit 1
fi

for tool in jq fsck.erofs dump.erofs; do
    command -v "${tool}" >/dev/null || {
        echo "missing required tool: ${tool}" >&2
        exit 1
    }
done

# Root in a container, sudo on a CI runner.
if [ "$(id -u)" -eq 0 ]; then
    sudo=()
else
    sudo=(sudo)
fi

workdir=$(mktemp -d)
mnt="${workdir}/mnt"
out="${workdir}/out"
mkdir -p "${mnt}" "${out}"

mounted=""
cleanup() {
    # Unmount before removing anything, on the failure paths too: leaving a
    # mount behind wedges the rest of the job.
    [ -n "${mounted}" ] && "${sudo[@]}" umount "${mnt}" || true
    rm -rf "${workdir}"
}
trap cleanup EXIT

echo "::group::build ${name} as erofs"
"${apko}" build "${yaml}" "${name}:build" "${out}/" --format=erofs --arch=host
echo "::endgroup::"

# Resolve the layer blob through the OCI index, as docs/erofs.md describes.
[ "$(jq -r '.manifests | length' "${out}/index.json")" = 1 ] ||
    { echo "expected a single manifest for --arch=host" >&2; exit 1; }
manifest=$(jq -r '.manifests[0].digest | split(":")[1]' "${out}/index.json")
[[ "${manifest}" =~ ^[0-9a-f]{64}$ ]] ||
    { echo "bad manifest digest: ${manifest}" >&2; exit 1; }

# A single layer is what apko produces today; `layering` with `format: erofs`
# is rejected during validation.  Loosen this when splitting returns.
[ "$(jq -r '.layers | length' "${out}/blobs/sha256/${manifest}")" = 1 ] ||
    { echo "expected a single layer" >&2; exit 1; }
layer=$(jq -r '.layers[0].digest | split(":")[1]' "${out}/blobs/sha256/${manifest}")
[[ "${layer}" =~ ^[0-9a-f]{64}$ ]] ||
    { echo "bad layer digest: ${layer}" >&2; exit 1; }

blob="${out}/blobs/sha256/${layer}"
mediatype=$(jq -r '.layers[0].mediaType' "${out}/blobs/sha256/${manifest}")
[ "${mediatype}" = "application/vnd.erofs" ] ||
    { echo "unexpected layer mediaType: ${mediatype}" >&2; exit 1; }

# The blob is stored uncompressed, so digest == diffID == sha256 of the
# filesystem image itself.  Anything else means a compression step crept in.
echo "${layer}  ${blob}" | sha256sum -c -

echo "::group::fsck.erofs and dump.erofs"
fsck.erofs -d3 "${blob}"
dump.erofs "${blob}" | head -20
echo "::endgroup::"

echo "::group::kernel mount"
if ! grep -qw erofs /proc/filesystems; then
    "${sudo[@]}" modprobe erofs ||
        { echo "kernel erofs driver unavailable; install linux-modules-extra-$(uname -r)" >&2; exit 1; }
    grep -qw erofs /proc/filesystems ||
        { echo "erofs absent from /proc/filesystems after modprobe" >&2; exit 1; }
fi

"${sudo[@]}" mount -t erofs -o ro "${blob}" "${mnt}"
mounted=1
mountpoint -q "${mnt}"
echo "::endgroup::"

# Cross-check apko's own reader against the kernel's: same paths, same mode
# bits, same ownership, same symlink targets.  This is what would catch a
# go-erofs regression in the setuid/setgid/sticky bits, which is the class of
# bug that motivated the v0.3.1 bump.
echo "::group::compare 'apko erofs ls' against the mounted tree"
"${apko}" erofs ls "${out}/" >"${workdir}/ls.raw"

# Both listings are whitespace-delimited, so a path containing a space would
# silently misalign them.  Fail instead.
if grep -qE '[[:space:]]$|  +->' "${workdir}/ls.raw"; then
    echo "unexpected whitespace in listing; comparison would be unreliable" >&2
    exit 1
fi

# ls columns: mode uid/gid size date time path [-> target]
awk '{
    line = $1 " " $2 " " $6
    if ($7 == "->") line = line " -> " $8
    print line
}' "${workdir}/ls.raw" | LC_ALL=C sort >"${workdir}/from-apko"

find "${mnt}" -mindepth 1 -printf '%M\t%U/%G\t%P\t%y\t%l\n' |
    awk -F'\t' '{
        line = $1 " " $2 " " $3
        if ($4 == "l") line = line " -> " $5
        print line
    }' | LC_ALL=C sort >"${workdir}/from-kernel"

if ! diff -u "${workdir}/from-kernel" "${workdir}/from-apko"; then
    echo "'apko erofs ls' disagrees with the kernel about the layer contents" >&2
    exit 1
fi
echo "$(wc -l <"${workdir}/from-apko") entries agree"
echo "::endgroup::"

"${sudo[@]}" umount "${mnt}"
mounted=""
if mountpoint -q "${mnt}"; then
    echo "${mnt} still mounted after umount" >&2
    exit 1
fi

echo "PASS: ${name} erofs layer mounts and matches 'apko erofs ls'"
