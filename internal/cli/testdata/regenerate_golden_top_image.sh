#!/bin/bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)

set -e -x

mkdir -p "${SCRIPT_DIR}/top_image.new"
(
  cd "${SCRIPT_DIR}/.."
  go run "../.." build \
    --include-paths="${SCRIPT_DIR}/.." \
    --lockfile=./testdata/image_on_top.apko.lock.json \
    ./testdata/image_on_top.apko.yaml  \
    topimage \
    ./testdata/top_image.new/
  rm -rf "${SCRIPT_DIR}/top_image"
  mv "${SCRIPT_DIR}/top_image.new" "${SCRIPT_DIR}/top_image"
)
