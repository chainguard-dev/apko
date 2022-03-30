#!/bin/sh

# Copyright 2022 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

function run() {

    if [[ ! -f "./apko" ]]; then
	echo "Building apko"
	make apko
    fi

    ./apko "$@"
}

function docker_run() {
    docker run --rm -w /apko -v $(pwd):/apko --entrypoint /apko/hack/run-devenv.sh apko-inception:latest run $@
}

case "$1" in
    "run")
        run ${@:4};;
    *)
	docker_run $@;;
esac

