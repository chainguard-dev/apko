#!/bin/bash


BASE_IMAGE=cgr.dev/chainguard/wolfi-base:latest
BASE_IMAGE_DIR=./base_image
APKINDEX_DIR=./apkindexes
FS_DUMP_DIR=./fs_dump

# Pull base image
crane pull "$BASE_IMAGE" "$BASE_IMAGE_DIR" --format=oci
# Prepare apkindex for base image
mkdir -p "$FS_DUMP_DIR"
crane export "$BASE_IMAGE" "$FS_DUMP_DIR/fs.tar"
tar -C "$FS_DUMP_DIR" -xf "$FS_DUMP_DIR/fs.tar"
mkdir -p "$APKINDEX_DIR/x86_64/"
cp "$FS_DUMP_DIR/lib/apk/db/installed" "$APKINDEX_DIR/x86_64/APKINDEX"