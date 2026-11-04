#!/bin/sh

# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu
crane registry serve --address "127.0.0.1:${REGISTRY_PORT}" &
daemon=$!
trap 'kill "$daemon" 2>/dev/null || true' EXIT
trap 'exit 1' HUP INT TERM
until crane catalog --insecure "localhost:${REGISTRY_PORT}" >/dev/null 2>&1; do
  kill -0 "$daemon" 2>/dev/null || exit 1
  sleep 0.1
done
printf '\n::service-ready::\n'
wait "$daemon"
exit 1
