#!/bin/sh

# Copyright 2022 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

BUILDER_ALPINE_TAG="3.16.0@sha256:686d8c9dfa6f3ccfc8230bc3178d23f84eeaf7e457f36f271ab1acc53015037c"
DEVENV_IMAGE_TARBALL="apko-inception.tar.gz"
IMAGE_TAG="apko-inception"

checkrepo() {
    grep "module chainguard.dev/apko" go.mod &> /dev/null && return
    echo;
    echo "Please run me from the apko repository root. Thank you!";
    echo
    exit 1;
}

run_builder() {
    if ! (docker inspect apko-inception:latest &> /dev/null ); then
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
    go run main.go build --sbom=false ./examples/apko-devenv.yaml ${IMAGE_TAG} ./_output/${DEVENV_IMAGE_TARBALL}
    chown ${BUILD_UID}:${BUILD_GID} _output/${DEVENV_IMAGE_TARBALL}
}

load_image() {
    set -e
    docker rmi ${IMAGE_TAG}:latest 2>&1 || :
    docker load < _output/${DEVENV_IMAGE_TARBALL}
}

run() {
    docker run --rm -w /apko -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd):/apko -ti ${IMAGE_TAG}:latest hack/make-devenv.sh setup
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
