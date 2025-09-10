#!/bin/bash

# Script for building image on top of base with apko. Must be run from the root of github repository.

apko_binary="${1:-apko}"
BASE_IMAGE="${2:-cgr.dev/chainguard/wolfi-base:latest}"
OUTPUT_TAR="${3:-}"
ARCH="${4:-x86_64}"

EXAMPLE_DIR=./examples/on_top_of_base
BASE_IMAGE_DIR="$EXAMPLE_DIR/base_image"
APKINDEX_DIR="$EXAMPLE_DIR/apkindexes"
FS_DUMP_DIR="$EXAMPLE_DIR/fs_dump"

# Pull base image
crane pull "$BASE_IMAGE" "$BASE_IMAGE_DIR" --format=oci
# Prepare apkindex for base image
mkdir -p "$FS_DUMP_DIR"
crane export "$BASE_IMAGE" "$FS_DUMP_DIR/fs.tar"
tar -C "$FS_DUMP_DIR" -xf "$FS_DUMP_DIR/fs.tar"
mkdir -p "$APKINDEX_DIR/$ARCH/"
cp "$FS_DUMP_DIR/lib/apk/db/installed" "$APKINDEX_DIR/$ARCH/APKINDEX"

"$apko_binary" lock "$EXAMPLE_DIR/base_image.yaml" --arch="$ARCH"

if [ -n "$OUTPUT_TAR" ]; then
    # Output to tar file
    "$apko_binary" build --arch="$ARCH" "$EXAMPLE_DIR/base_image.yaml" base_image:latest "$OUTPUT_TAR" --lockfile="$EXAMPLE_DIR/base_image.lock.json" --sbom=False
else
    # Output to directory (original behavior)
    mkdir -p "$EXAMPLE_DIR/top_image"
    "$apko_binary" build --arch="$ARCH" "$EXAMPLE_DIR/base_image.yaml" base_image:latest "$EXAMPLE_DIR/top_image/" --lockfile="$EXAMPLE_DIR/base_image.lock.json" --sbom=False
fi
