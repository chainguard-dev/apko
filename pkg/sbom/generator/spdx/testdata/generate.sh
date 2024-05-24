#!/bin/sh
curl -q https://packages.wolfi.dev/os/x86_64/font-ubuntu-0.869-r1.apk | tar Ozx var/lib/db/sbom/font-ubuntu-0.869-r1.spdx.json >font-ubuntu.spdx.json 2>/dev/null
curl -q https://packages.wolfi.dev/os/x86_64/libattr1-2.5.1-r2.apk | tar Ozx var/lib/db/sbom/libattr1-2.5.1-r2.spdx.json >libattr1.spdx.json 2>/dev/null
