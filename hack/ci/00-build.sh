#!/usr/bin/env bash

# Copyright 2023 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

set -ex

OUTPUT_TAR="output.tar"
REF="apko.local/ci-testing:test"

trap "rm -f ${OUTPUT_TAR}" EXIT

for f in examples/alpine-base-rootless.yaml examples/wolfi-base.yaml; do
  echo "=== building $f"

  REF="apko.local/ci-testing:$(basename ${f})"
  "${APKO}" build "${f}" "${REF}" "${OUTPUT_TAR}"

  # Subtest #1: Does it load?
  ARCH_REF="$(docker load < output.tar | grep "Loaded image" | sed 's/^Loaded image: //' | head -1)"

  # Subtest #2: Can we run it?
  docker run --rm "${ARCH_REF}" echo hello | grep hello
done
