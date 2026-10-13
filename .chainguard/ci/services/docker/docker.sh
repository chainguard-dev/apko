#!/bin/sh

# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu
if [ "$(id -u)" != 0 ]; then
  echo "docker service requires a root job" >&2
  exit 1
fi
# Guest init binds this path to scratch: Docker's overlay store cannot use
# the erofs guest root's overlay as its upper filesystem.
set -- dockerd --host=unix:///var/run/docker.sock \
  --data-root=/var/lib/chainguard-microvm/docker --storage-driver=overlay2
for ca in /usr/local/share/ca-certificates/microvm-guest-ca-*.crt; do
  [ -f "$ca" ] || continue
  set -- "$@" --add-runtime=cg-trust=/usr/local/bin/cg-runc-trust --default-runtime=cg-trust
  break
done
"$@" &
daemon=$!
trap 'kill "$daemon" 2>/dev/null || true' EXIT
trap 'exit 1' HUP INT TERM
until docker --host=unix:///var/run/docker.sock info >/dev/null 2>&1; do
  kill -0 "$daemon" 2>/dev/null || exit 1
  sleep 0.1
done
printf '\n::service-ready::\n'
# With set -e, a nonzero daemon exit becomes the wrapper's exit status.
wait "$daemon"
# Even a clean daemon exit is unexpected while the job still needs it.
exit 1
