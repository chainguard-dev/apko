#!/usr/bin/env bash

# Copyright 2025 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

# Tests that an apko-built image contains expected certificates in both the CA
# bundle and Java truststore, and that running update-ca-certificates doesn't
# change them.
#
# Usage: hack/test-certificates.sh <yaml> <fingerprint> [<fingerprint> ...]
#
# Example:
#   hack/test-certificates.sh ./examples/certificates.yaml \
#     "E7:05:70:A9:..." "9B:2A:33:9F:..."

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <yaml> <fingerprint> [<fingerprint> ...]"
    exit 1
fi

yaml="$1"
shift
fingerprints=("$@")

name=$(basename "${yaml}" .yaml)
image="${name}:build"
image_arch="${name}:build-amd64"
tarball="/tmp/${name}.tar"

# Gets all certificate fingerprints from a PEM stream, sorted, so two outputs can
# be semantically compared.
get_fingerprints() {
    local cert=""
    while IFS= read -r line; do
        case "$line" in
            "-----BEGIN CERTIFICATE-----")
                cert="$line"$'\n' ;;
            "-----END CERTIFICATE-----")
                cert+="$line"
                echo "$cert" | openssl x509 -noout -fingerprint -sha256 2>/dev/null
                cert="" ;;
            *)
                [[ -n "$cert" ]] && cert+="$line"$'\n' || true ;;
        esac
    done | sort
}

# Verifies that fingerprints file contains at least N certs and all expected fingerprints.
verify_fingerprints() {
    local file="$1"
    local min_count="$2"
    local store_name="$3"

    local count
    count=$(wc -l < "$file")
    if [ "$count" -lt "$min_count" ]; then
        echo "Expected at least $min_count certificates in $store_name, found $count"
        exit 1
    fi

    for fp in "${fingerprints[@]}"; do
        grep "$fp" "$file"
    done
    echo "$store_name contains all expected certificates."
}

# Build the image.
make apko
./apko build "${yaml}" "${image}" "${tarball}" --arch amd64
docker load < "${tarball}"

# Get fingerprints from CA bundle and Java truststore before update-ca-certificates.
docker run --rm "${image_arch}" "cat /etc/ssl/certs/ca-certificates.crt" | get_fingerprints > /tmp/ca-bundle-fingerprints.txt
docker run --rm "${image_arch}" "trust extract --filter=ca-anchors --purpose=server-auth --format=pem-bundle /tmp/certs.pem && cat /tmp/certs.pem" | get_fingerprints > /tmp/java-truststore-fingerprints.txt

# Verify both stores contain base certs and all expected certificates.
verify_fingerprints /tmp/ca-bundle-fingerprints.txt 10 "CA bundle"
verify_fingerprints /tmp/java-truststore-fingerprints.txt 10 "Java truststore"

# Run update-ca-certificates and get fingerprints from both stores after.
docker run --rm "${image_arch}" "apk add ca-certificates && update-ca-certificates && cat /etc/ssl/certs/ca-certificates.crt" | get_fingerprints > /tmp/ca-bundle-updated-fingerprints.txt
docker run --rm "${image_arch}" "apk add ca-certificates && update-ca-certificates && trust extract --filter=ca-anchors --purpose=server-auth --format=pem-bundle /tmp/certs.pem && cat /tmp/certs.pem" | get_fingerprints > /tmp/java-truststore-updated-fingerprints.txt

# Verify that the stores are semantically identical before and after update-ca-certificates.
diff /tmp/ca-bundle-fingerprints.txt /tmp/ca-bundle-updated-fingerprints.txt
echo "CA bundles before and after update-ca-certificates are identical."

diff /tmp/java-truststore-fingerprints.txt /tmp/java-truststore-updated-fingerprints.txt
echo "Java truststores before and after update-ca-certificates are identical."
