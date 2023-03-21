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
    - maven
archs:
  - x86_64
  - aarch64
EOF

# Publish image to registry
./apko publish --debug "${APKO_CONFIG}" "${REF}"

# Subtest #1: Can we run it?
# TODO: re-enable when we can run something
# docker pull "${REF}"
# docker run --entrypoint mvn --rm "${REF}" --version

# Subtest #2: Dowload SBOM and check that it contains
# files derived from package SBOMs melange produces in /var/lib/db/sbom
cosign download sbom --platform=linux/amd64 "${REF}" | tee ci-testing.sbom.json
HAS_FILES="$(cat ci-testing.sbom.json | jq 'keys | contains(["files"])')"
if [[ "${HAS_FILES}" != "true" ]]; then
  echo "SBOM does not have files. Exiting."
  exit 1
fi
