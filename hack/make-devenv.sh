#!/bin/sh

# Copyright 2022 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

BUILDER_ALPINE_TAG="edge@sha256:3e44438281baf26907675b99c9a4a421c4d4a57c954120327e703aa8329086bd"
DEVENV_IMAGE_TARBALL="apko-inception.tar.gz"
IMAGE_TAG="apko-inception"
ARCH=$(uname -m)

# Map apk-style arch string to the OCI-style equivalent
case "$ARCH" in
    "x86")
        ARCH="_386";;
    "x86_64")
        ARCH="amd64";;
    "aarch64")
        ARCH="arm64";;
    "armhf")
        ARCH="armv6";;
esac

checkrepo() {
    grep "module chainguard.dev/apko" go.mod >/dev/null 2>&1 && return
    echo;
    echo "Please run me from the apko repository root. Thank you!";
    echo
    exit 1;
}

run_builder() {
    if ! (docker inspect apko-inception:latest-$ARCH >/dev/null 2>&1 ); then
        set -e
        mkdir _output > /dev/null 2>&1 || : 
        docker run --rm -v $(pwd):/apko -w /apko -ti \
            -e BUILD_UID=$(id -u) -e BUILD_GID=$(id -g) \
            alpine:${BUILDER_ALPINE_TAG} \
            /bin/sh hack/make-devenv.sh build_image
        load_image
        rm _output/${DEVENV_IMAGE_TARBALL}
    fi
    run
}

build_image() {
    set -e
    cat /etc/os-release
    apk add go
    go run main.go build ./examples/apko-devenv.yaml ${IMAGE_TAG}:latest ./_output/${DEVENV_IMAGE_TARBALL} --sbom=false --arch=$ARCH
    chown ${BUILD_UID}:${BUILD_GID} _output/${DEVENV_IMAGE_TARBALL}
}

load_image() {
    set -e
    docker rmi ${IMAGE_TAG}:latest-$ARCH 2>&1 || :
    docker load < _output/${DEVENV_IMAGE_TARBALL}
}

run() {
    docker run --rm -w /apko -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd):/apko -ti ${IMAGE_TAG}:latest-$ARCH hack/make-devenv.sh setup
}

setup() {
    echo
    echo "Welcome to the apko development environment!"
    echo
    echo
    alias ll="ls -l"
    export PS1="[apko] ❯ "
    sh -i
}

checkrepo
case "$1" in
    "")
        run_builder;;
    "build_image")
        build_image;;
    "run")
        run;;
    "setup")
        setup;;
esac
