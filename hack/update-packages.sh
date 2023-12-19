#!/usr/bin/env bash

# Copyright 2023 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

set -ex

(cd internal/cli/testdata && \
  melange build --arch arm64 --arch amd64 -r https://packages.wolfi.dev/os -k https://packages.wolfi.dev/os/wolfi-signing.rsa.pub --signing-key ./melange.rsa pretend-baselayout.melange.yaml && \
  melange build --arch arm64 --arch amd64 -r https://packages.wolfi.dev/os -k https://packages.wolfi.dev/os/wolfi-signing.rsa.pub --signing-key ./melange.rsa replayout.melange.yaml)
(cd internal/cli &&
  apko lock ./testdata/apko.yaml)
