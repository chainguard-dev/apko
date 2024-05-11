# testdata

This directory contains useful artifacts for tests.

Notably:

* `alpine-316/` - directory with some of the contents of `https://dl-cdn.alpinelinux.org/alpine/v3.16/main/aarch64/`
    * `APKINDEX.tar.gz`
    * `alpine-baselayout-3.2.0.-r23.apk`. It should not be read, only used to validate bytes.
* `alpine-317/` - directory with some of the contents of `https://dl-cdn.alpinelinux.org/alpine/v3.17/main/aarch64/`. Note that these are from 3.17.
    * `APKINDEX.tar.gz` - It really only serves the purpose of being a valid `APKINDEX.tar.gz` but different from the one in the `alpine-316/`, so we can compare which one is read.
    * `cache/alpine-baselayout-3.4.0-r0.apk`
    * `cache/alpine-baselayout-3.2.0-r23.apk` - a copy of `alpine-baselayout-3.4.0-r0.apk`, but with different versions. It should not be read, only used to validate that this one is read versus the one in the root of this directory.
* `rsa256-signed` - repository signed with RSA256 using SHA2-256
    * `rebuild.sh` documents how to recreate the test data
* `root/lib/apk/db/` - prebuilt contents of what should be in a filesystem, to compare the results of tests.
* `replaces/`
    * `melange.yaml` - melange config to build the apk
    * `replaces-0.0.1-r0` - APK with multiple `replaces = ` lines
