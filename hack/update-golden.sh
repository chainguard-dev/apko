#!/bin/sh

# Copyright 2023 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

set -ex

(cd internal/cli && \
  rm -rf ./testdata/golden && \
  mkdir -p ./testdata/golden/sboms && \
  apko build --sbom-formats spdx --sbom-path ./testdata/golden/sboms ./testdata/apko.yaml golden:latest ./testdata/golden)
