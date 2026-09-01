#!/usr/bin/env bash

# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

# End-to-end check of an apko --format=erofs build: the layer blob is a real
# EROFS filesystem that erofs-utils accepts and the kernel will mount,
# `apko erofs ls` reports the same tree the kernel does, and
# `apko erofs mount` / `apko erofs umount` drive that mount themselves.
#
# The same yaml is then built again with `layering`, and the check repeats
# against the overlayfs stack the kernel assembles from those layers.
#
# Usage: hack/test-erofs.sh <yaml>
#
# Example:
#   hack/test-erofs.sh ./examples/wolfi-base.yaml
#
# Requires: jq, mountpoint (util-linux), erofs-utils (fsck.erofs, dump.erofs),
# the kernel erofs driver, and root (or passwordless sudo) for the mount.  Set APKO to use a binary
# other than ./apko.  The --rw section needs a TMPDIR that overlayfs accepts
# as an upperdir, which rules out tmpfs on older kernels.

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <yaml>"
    exit 1
fi

yaml="$1"
apko="${APKO:-./apko}"
name=$(basename "${yaml}" .yaml)
# Written inside DEST by `apko erofs mount`, read back by `apko erofs umount`.
state=".apko-erofs-mount.json"

if [ ! -x "${apko}" ]; then
    echo "no apko binary at ${apko}; run 'make apko' first" >&2
    exit 1
fi
# Resolved once: the mount sections run it through sudo.
apko=$(readlink -f "${apko}")

for tool in jq mountpoint fsck.erofs dump.erofs; do
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

cleanup() {
    # Unmount before removing anything, on the failure paths too: leaving a
    # mount behind wedges the rest of the job.  Everything this script mounts
    # lives under workdir, so take down whatever is still there, deepest first,
    # rather than tracking each mount separately.
    local mp
    while read -r mp; do
        "${sudo[@]}" umount "${mp}" || true
    done < <(awk -v pfx="${workdir}/" 'index($2, pfx) == 1 { print $2 }' \
        /proc/self/mounts | LC_ALL=C sort -r)
    # apko ran under sudo, so parts of workdir are root-owned by now.  Don't
    # let a failure here mask the script's own exit status.
    "${sudo[@]}" rm -rf "${workdir:?}" ||
        echo "warning: ${workdir} not fully removed" >&2
}
trap cleanup EXIT

fail() {
    echo "$*" >&2
    exit 1
}

assert_mounted() {
    mountpoint -q "$1" || fail "expected $1 to be a mountpoint"
}

assert_not_mounted() {
    if mountpoint -q "$1"; then
        fail "expected $1 not to be a mountpoint"
    fi
}

assert_absent() {
    [ ! -e "$1" ] || fail "expected $1 to be gone"
}

# assert_state DEST JQ-EXPR EXPECTED.  The state file is written 0600 by root,
# so it is read back through sudo.
assert_state() {
    local got
    got=$("${sudo[@]}" jq -r "$2" "$1/${state}")
    [ "${got}" = "$3" ] || fail "state of $1: $2 is ${got}, expected $3"
}

# plant_state DEST MOUNTPOINT.  Writes the state file an attacker with write
# access to DEST would, naming MOUNTPOINT as the thing to take down.
plant_state() {
    jq -n --arg dest "$1" --arg mp "$2" '{
        schemaVersion: 1,
        mode: "kernel",
        source: "tampered",
        dest: $dest,
        created: "2026-01-01T00:00:00Z",
        writable: false,
        mounts: [$mp]
    }' >"$1/${state}"
}

# Both listings are whitespace-delimited, so a path containing a space would
# silently misalign them.  Fail instead.
check_ls_whitespace() {
    if grep -qE '[[:space:]]$|  +->' "$1"; then
        fail "unexpected whitespace in listing; comparison would be unreliable"
    fi
}

# Both listings below collapse to "mode uid/gid path [-> target]" so they can
# be diffed.  `apko erofs ls` columns: mode uid/gid size date time path
# [-> target].
normalize_ls() {
    awk '{
        line = $1 " " $2 " " $6
        if ($7 == "->") line = line " -> " $8
        print line
    }' | LC_ALL=C sort
}

# The walk runs privileged.  The image intentionally contains mode-0700
# directories owned by other uids (root, usr/man, var/adm), which an
# unprivileged find cannot descend into; `apko erofs ls` reads the image
# directly and is not subject to that, so the two would disagree for a reason
# that has nothing to do with apko.
tree_listing() {
    "${sudo[@]}" find "$1" -mindepth 1 -printf '%M\t%U/%G\t%P\t%y\t%l\n' |
        awk -F'\t' '{
            line = $1 " " $2 " " $3
            if ($4 == "l") line = line " -> " $5
            print line
        }' | LC_ALL=C sort
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

"${sudo[@]}" mount -t erofs -o ro "${blob}" "${mnt}"
assert_mounted "${mnt}"
echo "::endgroup::"

# Cross-check apko's own reader against the kernel's: same paths, same mode
# bits, same ownership, same symlink targets.  This is what would catch a
# go-erofs regression in the setuid/setgid/sticky bits, which is the class of
# bug that motivated the v0.3.1 bump.
echo "::group::compare 'apko erofs ls' against the mounted tree"
"${apko}" erofs ls "${out}/" >"${workdir}/ls.raw"
check_ls_whitespace "${workdir}/ls.raw"

normalize_ls <"${workdir}/ls.raw" >"${workdir}/from-apko"
tree_listing "${mnt}" >"${workdir}/from-kernel"

if ! diff -u "${workdir}/from-kernel" "${workdir}/from-apko"; then
    fail "'apko erofs ls' disagrees with the kernel about the layer contents"
fi
echo "$(wc -l <"${workdir}/from-apko") entries agree"
echo "::endgroup::"

"${sudo[@]}" umount "${mnt}"
assert_not_mounted "${mnt}"

# Everything above drives mount(8) directly.  The rest drives `apko erofs
# mount` and `apko erofs umount`, which is the only place their orchestration
# -- layout, state file, teardown order -- runs against a real kernel.

echo "::group::apko erofs mount (read-only image)"
ro="${workdir}/ro"
"${sudo[@]}" "${apko}" erofs mount "${out}" "${ro}"

# One layer read-only: overlayfs is skipped and the layer is mounted straight
# at merged, so layers/, upper/ and work/ are never created.
assert_mounted "${ro}/merged"
assert_absent "${ro}/layers"
assert_absent "${ro}/upper"

assert_state "${ro}" .mode kernel
assert_state "${ro}" .dest "${ro}"
assert_state "${ro}" .writable false
assert_state "${ro}" '.mounts | join(",")' "${ro}/merged"

tree_listing "${ro}/merged" >"${workdir}/from-mount"
if ! diff -u "${workdir}/from-apko" "${workdir}/from-mount"; then
    fail "'apko erofs mount' exposes a different tree than 'apko erofs ls'"
fi

"${sudo[@]}" "${apko}" erofs umount "${ro}"
assert_not_mounted "${ro}/merged"
assert_absent "${ro}/merged"
assert_absent "${ro}/${state}"
echo "::endgroup::"

echo "::group::apko erofs mount --rw (overlay, writes preserved)"
rw="${workdir}/rw"
"${sudo[@]}" "${apko}" erofs mount --rw "${out}" "${rw}"

# --rw always composes through overlayfs, single layer or not.
assert_mounted "${rw}/layers/00"
assert_mounted "${rw}/merged"
assert_state "${rw}" .writable true
# LIFO: merged comes down before the layer it is stacked on.
assert_state "${rw}" '.mounts | join(",")' "${rw}/merged,${rw}/layers/00"

echo "written through the mount" | "${sudo[@]}" tee "${rw}/merged/sentinel" >/dev/null
"${sudo[@]}" "${apko}" erofs umount "${rw}"
assert_not_mounted "${rw}/merged"
assert_absent "${rw}/merged"
assert_absent "${rw}/layers"
assert_absent "${rw}/work"
assert_absent "${rw}/${state}"
# upper is the one directory umount must leave alone once something has been
# written through it: removing it would silently discard those writes.
[ -f "${rw}/upper/sentinel" ] ||
    fail "umount discarded the writes made through a --rw mount"
# And because it is still there, a second --rw mount at the same DEST has to
# refuse rather than stack this session's writes under the next one.
if "${sudo[@]}" "${apko}" erofs mount --rw "${out}" "${rw}"; then
    fail "--rw mount reused an upper left behind by an earlier mount"
fi
assert_not_mounted "${rw}/merged"

# An upper nothing was written through is not worth keeping, so that round trip
# leaves DEST clean and immediately reusable.
rw2="${workdir}/rw2"
"${sudo[@]}" "${apko}" erofs mount --rw "${out}" "${rw2}"
"${sudo[@]}" "${apko}" erofs umount "${rw2}"
assert_absent "${rw2}/upper"
"${sudo[@]}" "${apko}" erofs mount --rw "${out}" "${rw2}"
"${sudo[@]}" "${apko}" erofs umount "${rw2}"
echo "::endgroup::"

echo "::group::apko erofs mount (raw blob)"
blobmnt="${workdir}/blobmnt"
"${sudo[@]}" "${apko}" erofs mount "${blob}" "${blobmnt}"
assert_mounted "${blobmnt}"
# A blob has no enclosing directory to hold state, so umount has to fall back
# to treating dest as a single mountpoint.
"${sudo[@]}" "${apko}" erofs umount "${blobmnt}"
assert_not_mounted "${blobmnt}"
echo "::endgroup::"

echo "::group::apko erofs umount rejects a tampered state file"
# The state file lives inside DEST, so whoever can write there decides what a
# root umount is asked to take down.  Two shapes have to be refused: a
# mountpoint plainly outside DEST, and one named DEST/merged -- which the
# whitelist allows -- that is a symlink pointing out.  umount(8) canonicalizes
# its argument, so following the second lands on the decoy just as surely as
# the first.  Both check that the decoy is still mounted afterwards, which is
# the part a message-only check would miss.
decoy="${workdir}/decoy"
mkdir -p "${decoy}"
"${sudo[@]}" mount -t tmpfs -o size=1m tmpfs "${decoy}"
assert_mounted "${decoy}"

outside="${workdir}/tampered-outside"
mkdir -p "${outside}"
plant_state "${outside}" "${decoy}"
if "${sudo[@]}" "${apko}" erofs umount "${outside}"; then
    fail "umount accepted a state file naming a mount outside DEST"
fi
assert_mounted "${decoy}"
# A nonzero exit on its own would also match a crash before the check ran.
# The state file surviving untouched is what says it was refused.
[ -f "${outside}/${state}" ] ||
    fail "umount removed the state file it was supposed to refuse"

symlinked="${workdir}/tampered-symlink"
mkdir -p "${symlinked}"
ln -s "${decoy}" "${symlinked}/merged"
plant_state "${symlinked}" "${symlinked}/merged"
if "${sudo[@]}" "${apko}" erofs umount "${symlinked}"; then
    fail "umount followed a symlinked DEST/merged out of DEST"
fi
assert_mounted "${decoy}"
[ -f "${symlinked}/${state}" ] ||
    fail "umount removed the state file it was supposed to refuse"
[ -L "${symlinked}/merged" ] ||
    fail "umount disturbed the symlink instead of refusing it"

# The two refusals above are both decided before umount(2) is reached, so
# neither exercises UMOUNT_NOFOLLOW.  This does: a symlink pointing straight at
# a live mountpoint, handed in as DEST so nothing validates it first.  Without
# the flag the kernel would resolve it and take the tmpfs down.
ln -s "${decoy}" "${workdir}/decoy-link"
if "${sudo[@]}" "${apko}" erofs umount "${workdir}/decoy-link"; then
    fail "umount followed a symlink to a live mountpoint"
fi
assert_mounted "${decoy}"

"${sudo[@]}" umount "${decoy}"
echo "::endgroup::"

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
    fail "bad layered manifest digest: ${lmanifest}"
lmanifest="${lout}/blobs/sha256/${lmanifest}"

nlayers=$(jq -r '.layers | length' "${lmanifest}")
[ "${nlayers}" -gt 1 ] ||
    fail "expected more than one layer with layering, got ${nlayers}"

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
        fail "bad layer digest: ${digest}"
    lblob="${lout}/blobs/sha256/${digest#sha256:}"

    mediatype=$(jq -r ".layers[${i}].mediaType" "${lmanifest}")
    [ "${mediatype}" = "application/vnd.erofs" ] ||
        fail "unexpected mediaType on layer ${i}: ${mediatype}"
    echo "${digest#sha256:}  ${lblob}" | sha256sum -c -
    fsck.erofs -d3 "${lblob}" >/dev/null

    lmnt=$(printf '%s/layer%02d' "${workdir}" "${i}")
    mkdir -p "${lmnt}"
    "${sudo[@]}" mount -t erofs -o ro "${lblob}" "${lmnt}"
    assert_mounted "${lmnt}"

    # Every layer but the top one holds a package group, so it must carry that
    # group's files -- not just the ancestor directories and the partial
    # installed db it needs to describe them.  This is the shape the routing
    # bug produced.
    #
    # This assumes every group contributes at least one regular file besides
    # that db, which holds for the default config.  A group of packages that
    # ship only symlinks would false-fail here; relax it to "-type f -o -type
    # l" if you point the script at a yaml where that happens.
    if [ "${i}" -lt "$((nlayers - 1))" ]; then
        found=$("${sudo[@]}" find "${lmnt}" -type f \
            ! -path "${lmnt}/usr/lib/apk/db/installed" -print -quit)
        [ -n "${found}" ] || fail "layer ${i} holds no package files"
    fi

    lowers="${lmnt}${lowers:+:${lowers}}"
    i=$((i + 1))
done < <(jq -r '.layers[].digest' "${lmanifest}")

merged="${workdir}/merged"
mkdir -p "${merged}"
# No upperdir, so the overlay is read-only, which is all this needs and keeps
# a stray write from ending up in the comparison.
"${sudo[@]}" mount -t overlay overlay -o "ro,lowerdir=${lowers}" "${merged}"
assert_mounted "${merged}"
echo "::endgroup::"

echo "::group::compare 'apko erofs ls' against the overlay stack"
"${apko}" erofs ls "${lout}/" >"${workdir}/ls-layered.raw"
check_ls_whitespace "${workdir}/ls-layered.raw"
normalize_ls <"${workdir}/ls-layered.raw" >"${workdir}/from-apko-layered"
tree_listing "${merged}" >"${workdir}/from-kernel-layered"

if ! diff -u "${workdir}/from-kernel-layered" "${workdir}/from-apko-layered"; then
    fail "'apko erofs ls' disagrees with overlayfs about the merged tree"
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
        fail "bad tar layer digest: ${digest}"
    # --numeric-owner or GNU tar resolves the layer's uname/gname against the
    # runner's /etc/passwd, which has its own ids for lp, mail, news and uucp.
    "${sudo[@]}" tar -C "${tarroot}" --numeric-owner -xpf \
        "${tout}/blobs/sha256/${digest#sha256:}"
done < <(jq -r '.layers[].digest' "${tmanifest}")

tree_listing "${tarroot}" >"${workdir}/from-tar"
if ! diff -u "${workdir}/from-tar" "${workdir}/from-apko-layered"; then
    fail "the merged EROFS tree differs from the tar build of the same config"
fi
echo "::endgroup::"

"${sudo[@]}" umount "${merged}"
assert_not_mounted "${merged}"
for ((i = nlayers - 1; i >= 0; i--)); do
    lmnt=$(printf '%s/layer%02d' "${workdir}" "${i}")
    "${sudo[@]}" umount "${lmnt}"
    assert_not_mounted "${lmnt}"
done

echo "PASS: ${name} erofs layers mount, match 'apko erofs ls' single and layered,"
echo "      and round-trip through 'apko erofs mount' / 'apko erofs umount'"
