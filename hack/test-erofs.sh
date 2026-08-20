#!/usr/bin/env bash

# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

# End-to-end check of an apko --format=erofs build: the layer blob is a real
# EROFS filesystem that erofs-utils accepts and the kernel will mount, and
# `apko erofs ls` reports the same tree the kernel does.
#
# The same yaml is then built again with `layering`, and the check repeats
# against the overlayfs stack the kernel assembles from those layers.
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

# Every mountpoint this script creates, in the order it created them.  The
# layered section stacks an overlay on top of several erofs mounts, so cleanup
# has to come down in reverse.
mounts=()
cleanup() {
    # Unmount before removing anything, on the failure paths too: leaving a
    # mount behind wedges the rest of the job.  do_umount leaves gaps in the
    # array, so walk the indices that are actually set.
    local i
    for i in $(printf '%s\n' "${!mounts[@]}" | sort -rn); do
        "${sudo[@]}" umount "${mounts[i]}" 2>/dev/null || true
    done
    rm -rf "${workdir}"
}
trap cleanup EXIT

# do_mount records the mountpoint before mounting, so a mount that succeeds
# and then trips `set -e` somewhere later is still torn down.
do_mount() {
    local mp="${*: -1}"
    mounts+=("${mp}")
    "${sudo[@]}" mount "$@"
    mountpoint -q "${mp}"
}

do_umount() {
    local mp="$1" i
    "${sudo[@]}" umount "${mp}"
    if mountpoint -q "${mp}"; then
        echo "${mp} still mounted after umount" >&2
        exit 1
    fi
    for i in "${!mounts[@]}"; do
        if [ "${mounts[i]}" = "${mp}" ]; then
            unset 'mounts[i]'
        fi
    done
}

# normalize_apko_ls turns `apko erofs ls` output into a sorted
# "mode uid/gid path [-> target]" listing, comparable with normalize_kernel_ls.
# ls columns: mode uid/gid size date time path [-> target]
normalize_apko_ls() {
    local raw="$1" out="$2"

    # Both listings are whitespace-delimited, so a path containing a space
    # would silently misalign them.  Fail instead.
    if grep -qE '[[:space:]]$|  +->' "${raw}"; then
        echo "unexpected whitespace in listing; comparison would be unreliable" >&2
        exit 1
    fi

    awk '{
        line = $1 " " $2 " " $6
        if ($7 == "->") line = line " -> " $8
        print line
    }' "${raw}" | LC_ALL=C sort >"${out}"
}

# normalize_kernel_ls produces the same shape by walking a mounted tree.
#
# The walk runs privileged.  The image intentionally contains mode-0700
# directories owned by other uids (root, usr/man, var/adm), which an
# unprivileged find cannot descend into; `apko erofs ls` reads the image
# directly and is not subject to that, so the two would disagree for a reason
# that has nothing to do with apko.
normalize_kernel_ls() {
    local mp="$1" out="$2"

    "${sudo[@]}" find "${mp}" -mindepth 1 -printf '%M\t%U/%G\t%P\t%y\t%l\n' |
        awk -F'\t' '{
            line = $1 " " $2 " " $3
            if ($4 == "l") line = line " -> " $5
            print line
        }' | LC_ALL=C sort >"${out}"
}

echo "::group::build ${name} as erofs"
"${apko}" build "${yaml}" "${name}:build" "${out}/" --format=erofs --arch=host
echo "::endgroup::"

# Resolve the layer blob through the OCI index, as docs/erofs.md describes.
[ "$(jq -r '.manifests | length' "${out}/index.json")" = 1 ] ||
    { echo "expected a single manifest for --arch=host" >&2; exit 1; }
manifest=$(jq -r '.manifests[0].digest | split(":")[1]' "${out}/index.json")
[[ "${manifest}" =~ ^[0-9a-f]{64}$ ]] ||
    { echo "bad manifest digest: ${manifest}" >&2; exit 1; }

# Without `layering` in the config, apko emits exactly one layer.
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

do_mount -t erofs -o ro "${blob}" "${mnt}"
echo "::endgroup::"

# Cross-check apko's own reader against the kernel's: same paths, same mode
# bits, same ownership, same symlink targets.  This is what would catch a
# go-erofs regression in the setuid/setgid/sticky bits, which is the class of
# bug that motivated the v0.3.1 bump.
echo "::group::compare 'apko erofs ls' against the mounted tree"
"${apko}" erofs ls "${out}/" >"${workdir}/ls.raw"
normalize_apko_ls "${workdir}/ls.raw" "${workdir}/from-apko"
normalize_kernel_ls "${mnt}" "${workdir}/from-kernel"

if ! diff -u "${workdir}/from-kernel" "${workdir}/from-apko"; then
    echo "'apko erofs ls' disagrees with the kernel about the layer contents" >&2
    exit 1
fi
echo "$(wc -l <"${workdir}/from-apko") entries agree"
echo "::endgroup::"

do_umount "${mnt}"

########################################################################
# Multi-layer: the same rootfs split across one EROFS layer per package
# group.  Nothing else executes the split against a real kernel, and the
# overlay stack is the only thing that shows whether the layers actually
# compose back into the rootfs they came from.
########################################################################

layered_yaml="${workdir}/layered.yaml"
cp "${yaml}" "${layered_yaml}"
if ! grep -qE '^layering:' "${layered_yaml}"; then
    cat >>"${layered_yaml}" <<'EOF'

layering:
  strategy: origin
  budget: 4
EOF
fi

lout="${workdir}/out-layered"
tout="${workdir}/out-tar"
mkdir -p "${lout}" "${tout}"

# The tar build of the same config is the reference for what the split must
# preserve.  Both builds resolve from one lockfile, so a package published
# between them cannot make them differ.
lock="${workdir}/apko.lock.json"

echo "::group::build ${name} as layered erofs, and as layered tar to compare"
"${apko}" lock "${layered_yaml}" --output "${lock}" --arch=host
"${apko}" build "${layered_yaml}" "${name}:layered" "${lout}/" \
    --format=erofs --arch=host --lockfile "${lock}"
"${apko}" build "${layered_yaml}" "${name}:layered-tar" "${tout}/" \
    --arch=host --lockfile "${lock}"
echo "::endgroup::"

lmanifest=$(jq -r '.manifests[0].digest | split(":")[1]' "${lout}/index.json")
[[ "${lmanifest}" =~ ^[0-9a-f]{64}$ ]] ||
    { echo "bad layered manifest digest: ${lmanifest}" >&2; exit 1; }
lmanifest="${lout}/blobs/sha256/${lmanifest}"

nlayers=$(jq -r '.layers | length' "${lmanifest}")
[ "${nlayers}" -gt 1 ] ||
    { echo "expected more than one layer with layering, got ${nlayers}" >&2; exit 1; }

# Spec §3.8 rule 1 as apko produces it: every layer but the last is an
# overlay-lower, the last carries no role at all.
roles=$(jq -r '.layers[] | .annotations["org.erofs.role"] // "null"' "${lmanifest}")
expected=$(
    for ((i = 1; i < nlayers; i++)); do echo overlay-lower; done
    echo null
)
[ "${roles}" = "${expected}" ] || {
    echo "unexpected layer roles:" >&2
    printf '%s\n' "${roles}" >&2
    exit 1
}

echo "::group::mount ${nlayers} layers and stack them"
# overlayfs lists lowerdirs top-down (highest priority first) while OCI orders
# layers bottom-up, so each new layer is prepended.
lowers=""
i=0
while read -r digest; do
    [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] ||
        { echo "bad layer digest: ${digest}" >&2; exit 1; }
    lblob="${lout}/blobs/sha256/${digest#sha256:}"

    mediatype=$(jq -r ".layers[${i}].mediaType" "${lmanifest}")
    [ "${mediatype}" = "application/vnd.erofs" ] ||
        { echo "unexpected mediaType on layer ${i}: ${mediatype}" >&2; exit 1; }
    echo "${digest#sha256:}  ${lblob}" | sha256sum -c -
    fsck.erofs -d3 "${lblob}" >/dev/null

    lmnt=$(printf '%s/layer%02d' "${workdir}" "${i}")
    mkdir -p "${lmnt}"
    do_mount -t erofs -o ro "${lblob}" "${lmnt}"

    # Every layer but the top one holds a package group, so it must carry that
    # group's files -- not just the ancestor directories and the partial
    # installed db it needs to describe them.  This is the shape the routing
    # bug produced.
    if [ "${i}" -lt "$((nlayers - 1))" ]; then
        found=$("${sudo[@]}" find "${lmnt}" -type f \
            ! -path "${lmnt}/usr/lib/apk/db/installed" -print -quit)
        [ -n "${found}" ] ||
            { echo "layer ${i} holds no package files" >&2; exit 1; }
    fi

    lowers="${lmnt}${lowers:+:${lowers}}"
    i=$((i + 1))
done < <(jq -r '.layers[].digest' "${lmanifest}")

merged="${workdir}/merged"
mkdir -p "${merged}"
# No upperdir, so the overlay is read-only, which is all this needs and keeps
# a stray write from ending up in the comparison.
do_mount -t overlay overlay -o "ro,lowerdir=${lowers}" "${merged}"
echo "::endgroup::"

echo "::group::compare 'apko erofs ls' against the overlay stack"
"${apko}" erofs ls "${lout}/" >"${workdir}/ls-layered.raw"
normalize_apko_ls "${workdir}/ls-layered.raw" "${workdir}/from-apko-layered"
normalize_kernel_ls "${merged}" "${workdir}/from-kernel-layered"

if ! diff -u "${workdir}/from-kernel-layered" "${workdir}/from-apko-layered"; then
    echo "'apko erofs ls' disagrees with overlayfs about the merged tree" >&2
    exit 1
fi
echo "$(wc -l <"${workdir}/from-apko-layered") entries agree across ${nlayers} layers"
echo "::endgroup::"

# The tar split of the same config is the reference: unpacking its layers in
# order reproduces the rootfs both formats started from.  A directory that
# reaches no EROFS layer, or a file routed into a layer something else
# shadows, shows up here and nowhere else in this script.
echo "::group::compare the merged tree against the tar build of the same config"
tarroot="${workdir}/tarroot"
mkdir -p "${tarroot}"
tmanifest=$(jq -r '.manifests[0].digest | split(":")[1]' "${tout}/index.json")
tmanifest="${tout}/blobs/sha256/${tmanifest}"
while read -r digest; do
    [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] ||
        { echo "bad tar layer digest: ${digest}" >&2; exit 1; }
    "${sudo[@]}" tar -C "${tarroot}" -xpf "${tout}/blobs/sha256/${digest#sha256:}"
done < <(jq -r '.layers[].digest' "${tmanifest}")

normalize_kernel_ls "${tarroot}" "${workdir}/from-tar"
if ! diff -u "${workdir}/from-tar" "${workdir}/from-apko-layered"; then
    echo "the merged EROFS tree differs from the tar build of the same config" >&2
    exit 1
fi
echo "::endgroup::"

do_umount "${merged}"
for ((i = nlayers - 1; i >= 0; i--)); do
    do_umount "$(printf '%s/layer%02d' "${workdir}" "${i}")"
done

echo "PASS: ${name} erofs layers mount and match 'apko erofs ls', single and layered"
