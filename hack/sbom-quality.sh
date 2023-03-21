#!/usr/bin/env bash

set -ex

if [[ ! -f apko ]]; then
    echo "Please first run \"make apko\". Exiting."
    exit 1
fi

SBOM_FILENAME="sbom.json"
APKO_CONFIG="sbom-quality-test.yaml"
REGISTRY_BASE_IMAGE="index.docker.io/library/registry:2.8.1"
REGISTRY_CONTAINER_NAME="apko-sbom-quality-test"
REF="localhost:5000/sbom-quality:test"

trap "rm -f \"${SBOM_FILENAME}\" && \
rm -f \"${APKO_CONFIG}\" &&
docker rm -f \"${REGISTRY_CONTAINER_NAME}\"" EXIT

docker rm -f "${REGISTRY_CONTAINER_NAME}"
docker run --name "${REGISTRY_CONTAINER_NAME}" -d -p 5000:5000 "${REGISTRY_BASE_IMAGE}"

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

# Download the SBOM
cosign download sbom --platform=linux/amd64 "${REF}" | tee "${SBOM_FILENAME}"

# Test #1: Check that SBOMs contains files derived from
# package SBOMs melange produces in /var/lib/db/sbom
HAS_FILES="$(cat "${SBOM_FILENAME}" | jq 'keys | contains(["files"])')"
if [[ "${HAS_FILES}" != "true" ]]; then
  echo "SBOM does not have files. Exiting."
  exit 1
fi
