#!/usr/bin/env bash

# Copyright 2023 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

set -ex

# Go to repo root
cd "$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )/../"

if [[ ! -f apko ]]; then
    echo "Please first run \"make apko\". Exiting."
    exit 1
fi

for exe in `find hack/ci -name '*.sh' | sort`; do
    echo "Running test: ${exe}"
    ${exe}
done
