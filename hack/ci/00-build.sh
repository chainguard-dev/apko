#!/usr/bin/env bash

# Copyright 2023 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

set -ex

# Go to repo root
cd "$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )/../../"

if [[ ! -f apko ]]; then
    echo "Please first run \"make apko\". Exiting."
    exit 1
fi

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
    # TODO: re-enable all packages
    # (2023-03-21: busybix broken, "open lib64: Is directory")
    #- ca-certificates-bundle
    #- wolfi-baselayout
    #- glibc-locale-en
    #- busybox
    #- bash
    #- openjdk-17
    - wolfi-baselayout
archs:
  - x86_64
  - aarch64
EOF

# Build image
./apko build --debug "${APKO_CONFIG}" "${REF}" "${OUTPUT_TAR}"

# Subtest #1: Does it load?
ARCH_REF="$(docker load < output.tar | grep "Loaded image" | sed 's/^Loaded image: //' | head -1)"

# Subtest #2: Can we run it?
# TODO: re-enable when we can run something
# docker run --entrypoint mvn --rm "${ARCH_REF}" --version
