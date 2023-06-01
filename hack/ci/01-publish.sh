#!/usr/bin/env bash

# Copyright 2023 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

set -ex

REGISTRY_BASE_IMAGE="index.docker.io/library/registry:2.8.1"
REGISTRY_CONTAINER_NAME="ci-testing-registry"
REF="localhost:5000/ci-testing:test"
APKO_CONFIG="ci-testing.apko.yaml"
SBOM_FILENAME="ci-testing.sbom.json"

trap "rm -f ${APKO_CONFIG} &&
rm -f ${SBOM_FILENAME} && \
docker rm -f ${REGISTRY_CONTAINER_NAME}" EXIT

docker rm -f "${REGISTRY_CONTAINER_NAME}"
docker run --name "${REGISTRY_CONTAINER_NAME}" \
  -d -p 5000:5000 "${REGISTRY_BASE_IMAGE}"

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

# Publish image to registry
"${APKO}" publish --debug "${APKO_CONFIG}" "${REF}"

# Subtest #1: Can we run it
docker pull "${REF}"
docker run --entrypoint mvn --rm "${REF}" --version

# Subtest #2: Dowload SBOM and check that it contains
# files derived from package SBOMs melange produces in /var/lib/db/sbom
cosign download sbom --platform=linux/amd64 "${REF}" | tee ci-testing.sbom.json
HAS_FILES="$(cat ci-testing.sbom.json | jq 'keys | contains(["files"])')"
if [[ "${HAS_FILES}" != "true" ]]; then
  echo "SBOM does not have files. Exiting."
  exit 1
fi

# Subtest #3: Each platform should contain platform-specific etc/apk/arch file.
crane export --platform linux/amd64 "${REF}" | tar -Ox etc/apk/arch | grep x86_64
crane export --platform linux/arm64 "${REF}" | tar -Ox etc/apk/arch | grep aarch64
