#!/bin/sh
set -eux

# get one package
ln -sf ../alpine-316/alpine-baselayout-3.2.0-r23.apk

# generate test key
melange keygen test-rsa256.rsa

# generate APKINDEX
melange index -o APKINDEX.tar.gz *.apk

# sign with RSA256
# Using abuild from https://gitlab.alpinelinux.org/alpine/abuild/-/merge_requests/290
PATH=$PATH:~/upstream/abuild ABUILD_SHAREDIR=~/upstream/abuild CBUILD=aarch64 abuild-sign --private test-rsa256.rsa --type RSA256 APKINDEX.tar.gz

rm -f test-rsa256.rsa

