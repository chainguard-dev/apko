#!/bin/sh

set -euo pipefail

# Define an array of package name-version strings
packages=(
  "font-ubuntu-0.869-r1"
  "libattr1-2.5.1-r2"
  "logstash-8-8.15.3-r4"
  "logstash-8-compat-8.15.3-r4"
  "unbound-1.23.0-r0"
  "unbound-libs-1.23.0-r0"
  "unbound-config-1.23.0-r0"
)

# Base URL for downloading APKs
base_url="https://packages.wolfi.dev/os/x86_64"

# Loop through the array and process each package
for pkg in "${packages[@]}"; do
  url="${base_url}/${pkg}.apk"
  output_path="${pkg}.spdx.json"
  curl -q "$url" | tar Ozx "var/lib/db/sbom/${pkg}.spdx.json" >"$output_path" 2>/dev/null
done
