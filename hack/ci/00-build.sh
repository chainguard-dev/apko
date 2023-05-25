#!/usr/bin/env bash

# Copyright 2023 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

set -ex

APKO_CONFIG="ci-testing.apko.yaml"
OUTPUT_TAR="output.tar"
REF="localhost:5000/ci-testing:test"

trap "rm -f ${APKO_CONFIG} ${OUTPUT_TAR}" EXIT

cat > "${APKO_CONFIG}" << EOF
contents:
  repositories:
    - https://packages.wolfi.dev/os
  keyring:
    - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
  packages:
    - ca-certificates-bundle
    - glibc-locale-en
    - busybox
    - bash
    - openjdk-17
    - openjdk-17-default-jvm
    - maven
    - wolfi-baselayout
archs:
  - x86_64
  - aarch64
EOF

# Build image
"${APKO}" build --debug "${APKO_CONFIG}" "${REF}" "${OUTPUT_TAR}"

# Subtest #1: Does it load
ARCH_REF="$(docker load < output.tar | grep "Loaded image" | sed 's/^Loaded image: //' | head -1)"

# Subtest #2: Can we run it
docker run --entrypoint mvn --rm "${ARCH_REF}" --version
