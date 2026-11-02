#!/usr/bin/env bash

# Copyright 2023 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

set -ex

PORT=${PORT:-${RANDOM}}

# Docker treats 127.0.0.0/8 as an insecure registry, so its daemon pulls the
# published image straight from this one.
crane registry serve --address "localhost:${PORT}" &
REGISTRY_PID=$!

trap "rm -f *.sbom.json && \
kill ${REGISTRY_PID}" EXIT

until crane catalog --insecure "localhost:${PORT}" >/dev/null 2>&1; do
  kill -0 "${REGISTRY_PID}"
  sleep 0.1
done

for f in examples/wolfi-base.yaml; do
  echo "=== building $f"

  REF="localhost:${PORT}/ci-testing:$(basename ${f})"
  img=$("${APKO}" publish "${f}" "${REF}"  --arch amd64,arm64)

  # Run the image.
  docker run --rm ${img} echo hello | grep hello

  # Each platform should contain platform-specific etc/apk/arch file.
  crane export --platform linux/amd64 "${REF}" | tar -Ox etc/apk/arch | grep x86_64
  crane export --platform linux/arm64 "${REF}" | tar -Ox etc/apk/arch | grep aarch64
done
