#!/bin/sh
curl -q https://packages.wolfi.dev/os/x86_64/font-ubuntu-0.869-r1.apk | tar Ozx var/lib/db/sbom/font-ubuntu-0.869-r1.spdx.json >font-ubuntu.spdx.json 2>/dev/null

