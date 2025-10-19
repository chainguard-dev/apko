# Layering

This document describes how apko's layering implementation works and some rationale explaining why it works that way.

## Considerations

Primarily, we wanted something simple that can just be enabled and wouldn't require config authors to manually arrange layers.
While that amount of flexibility is powerful and makes sense for formats like `Dockerfile`, it wouldn't be a great fit for apko's simple model.
We've come up with simple heuristics that produce results that should be good enough for most people.
There is only one knob for tuning the number of layers, and we've left it open for extension, but the current layering config is very simple.

Another consideration was [reproducibility](https://www.chainguard.dev/unchained/reproducing-chainguards-reproducible-image-builds).
There are very interesting approaches like [nixery](https://nixery.dev/) that consider popularity of a package within the overall dependency graph, but we didn't want the layering strategy to rely on external data sources.
We want the layering decisions to be stable for reproducibility, so consulting an external index that can change over time wouldn't work.

Finally, we want the layering implementation to be effective.
Chainguard has a [large corpus of images](https://images.chainguard.dev/), so we were able to simulate the effects of these layering changes before rolling them out and also observe the actual effects in production.
Using our image corpus, we determined about 2/3 of our image data could be eliminated by sharing layers across images.
Similarly, we expect incremental changes to be much smaller between updates of a single image (based on the given budget, see below).

## Implementation

Support for layered apko images was added in [v0.27.0](https://github.com/chainguard-dev/apko/releases/tag/v0.27.0).

By default, apko will continue to lump everything into a single layer, but including the `layering` in an apko config will instruct apko to split filesystem contents across multiple layers.

For example:

```yaml
layering:
  strategy: origin
  budget: 10
```

Currently, the only layering strategy that has been implemented is the `origin` strategy, but we may revisit more complicated strategies in the future.

### Budget

Why include a budget?

Practically speaking, most container runtimes cannot support an infinite number of layers, so there is _some_ upper bound in how many layers we can use (today, containerd maxes out at 127).
Furthermore, not all images are used in the same way.
For "base" images, you probably don't want apko to use a huge number of layers because consumers of base images will append a bunch of their own layers, and at some point too many is too many.
For "application" images that are intended to be run directly, you don't usually expect someone to append any (or many) layers on top of them, so you may want apko to take advantage of more layers.

Thus, we shift the decision here to the user who will know more about how and where the image will be used.
Empirically, we have found a budget of 10 layers to be a decent balance between deduplication benefit and small fixed costs associated with each layer, but your mileage may vary.

### Strategy

The main purpose of this doc is to describe the `origin` layering strategy.

#### tl;dr

1. Lazily install all packages in the usual way.
1. Group packages together based on strategy and budget.
1. Partition the filesystem into real layers based on package grouping.
1. Any files not associated with a package are written to the "top" layer.

#### Lazy Install

One of the design goals of layering was to produce a layered rootfs that is identical to the non-layered rootfs.
If we try to construct each layer independently, we end up with slightly different results.

Why?

One example is [usr merge](https://wiki.debian.org/UsrMerge).
As part of merging everything under usr, we added a bunch of symlinked directories.
Installing a package with files under e.g. `/bin` when `/bin` is a symlink to `/usr/bin` will result in those files being written to `/usr/bin`.
One way to keep this behavior in a layered world is to start with "installing" every package in the usual way to a single filesystem.

This might seem inefficient because we would need to write every file twice, right?
In reality, this is fairly [efficient](https://github.com/chainguard-dev/apko/issues/781) because we don't actually write bytes to disk when we do this, we [just track file metadata](https://github.com/chainguard-dev/go-apk/pull/103) and [tar file offsets in memory](https://github.com/jonjohnsonjr/til/blob/main/post/tarfs.md).
We don't actually access those bytes until later when we walk the virtual filesystem to convert it into a concrete layer artifact.

Thanks to this lazy virtual filesystem approach, we actually have enough metadata about file ownership (i.e. which package a file belonged to) to retroactively perform layering while walking the filesystem.

#### Package Grouping

A naive strategy would be to lump every package into its own layer.
While this would be good for overall deduplication across images, it doesn't make efficient use of our layer budget.
We would like to apply some heuristics to combine related packages into layers so that we can stretch that layer budget further.

How?

We group packages together based on a small number of rules:

1. Group by `origin`.
1. Group by `replaces`.
1. Group outside budget.

##### By Origin

The `origin` of package really just refers to the build that produced it.
For wolfi, if a build is defined in `foo.yaml`, its origin is `foo`.

The rationale for grouping by origin is that packages within the same origin change together.
If there's a new version of `foo`, there will also be a new version of `foo-dev`, and you very likely would not want to mix and match packages across versions within an origin.
By that logic, grouping any packages from the same origin helps us double-dip on our layer budget by colocating these packages.

This heuristic works really well for a single image as it changes over time, but it has a minor failure mode when considering deduplication _across_ multiple images with similar packages.
As an example, if `example.com/image:latest` pulls in a huge package, `giant-package`, and `example.com/image:latest-dev` pulls in both `giant-package` and `giant-package-dev`, we would not get deduplication between the `latest` and `latest-dev` tags.
We have not found this to be common enough to warrant further effort.

As an example, chainguard's `go` image contains several packages that are part of the same `gcc` origin.
One easy way to determine which packages were grouped into a layer is to use their SBOM files as evidence.
Since those packages embed their SBOMs under `var/lib/db/sbom`, we can just list those files in any layer:

```
$ crane blob cgr.dev/chainguard/go@sha256:9d385ce368f85ee0b9463eb4e8734b8583b201a32c3f501cbef4cd1ac2de06bb | tar -tvz var/lib/db/sbom
drwxr-xr-x  0 root   root        0 Jun  2 10:31 var/lib/db/sbom
-rw-rw-rw-  0 root   root     3287 Jun  2 10:31 var/lib/db/sbom/gcc-15.1.0-r1.spdx.json
-rw-rw-rw-  0 root   root     3329 Jun  2 10:31 var/lib/db/sbom/libatomic-15.1.0-r1.spdx.json
-rw-rw-rw-  0 root   root     3308 Jun  2 10:31 var/lib/db/sbom/libgcc-15.1.0-r1.spdx.json
-rw-rw-rw-  0 root   root     3301 Jun  2 10:31 var/lib/db/sbom/libgo-15.1.0-r1.spdx.json
-rw-rw-rw-  0 root   root     3315 Jun  2 10:31 var/lib/db/sbom/libgomp-15.1.0-r1.spdx.json
-rw-rw-rw-  0 root   root     3343 Jun  2 10:31 var/lib/db/sbom/libquadmath-15.1.0-r1.spdx.json
-rw-rw-rw-  0 root   root     3349 Jun  2 10:31 var/lib/db/sbom/libstdc++-15.1.0-r1.spdx.json
-rw-rw-rw-  0 root   root     3377 Jun  2 10:31 var/lib/db/sbom/libstdc++-dev-15.1.0-r1.spdx.json
```

##### By Replaces

Rarely, but sometimes, you may want to install two packages that have overlapping and conflicting files.
By default, this will cause conflicts at install time, but APK has an escape hatch to deal with this: `replaces`.

You can declare that one package `replaces` another such that it will overwrite any conflicting files.
An example of this is [libxcrypt replacing old versions of libcrypt1](https://github.com/wolfi-dev/os/blob/4996d337875501f74f6a084fb7837d9e569a6dbf/libxcrypt.yaml#L13-L16).

One way to deal with this replaces directive would be to ensure layers are ordered correctly such that the last layer "wins" when the container runtime overlays each as a filesystem diff.
To continue with the above example, we would need to ensure that `libxcrypt` belonged to a layer that was "above" `libcrypt1`, so that the overlaid filesystem replaced any conflicts with `libcryptx` files.
This presents an interesting implementation challenge that I chose instead to sidestep.

Rather than trying to track these `replaces` relationships and sort layers in a corresponding order, we simply group both the replacer and the replacee packages into the same layer.
A downside of this is that "replaced" package layers won't be deduplicated with "nonreplaced" package layers, but given other implementation decisions, that was going to be true anyway!

All else being equal, grouping by `replaces` allows us to stretch that layer budget further, so we biased towards grouping.

I don't have a great public example of this because it happens so rarely, but trust me that this is how we handle that situation.

##### Overflow

After grouping by origin and replaces, we just sort by approximate size by summing the installed sizes of all packages within a layer (this information exists in each package's .PKGINFO) and take the top `$budget - 1`.
The penultimate layer group merges any remaining packages that didn't make the cut (given the budget).
In practice, this means all the smaller packages end up being grouped together.

Drawback?
Very commonly used packages that are small don't see any deduplication.
In practice, the potential savings you might gain from deduplicating very-commonly-used small packages together are dwarfed by the actual savings we see from prioritizing larger packages, so this has worked fine for us.
There is inherent overhead to pulling each layer at the HTTP layer (pardon the pun), so trying to dedupe anything under a few kilobytes is not really worth doing anyway.

Piggybacking on the previous example, we can look at packages in go's overflow layer:

```
$ crane blob cgr.dev/chainguard/go@sha256:3f284680a82c9bf0a2b8c8d856b9cce058a192fe04e64f606419756f2d138302 | tar -tvz var/lib/db/sbom

drwxr-xr-x  0 root   root        0 May 29 13:20 var/lib/db/sbom
-rw-rw-rw-  0 root   root     3148 May 29 13:20 var/lib/db/sbom/bash-5.2.37-r32.spdx.json
-rw-r--r--  0 root   root     1362 May 23  2024 var/lib/db/sbom/build-base-1-r8.spdx.json
-rw-rw-rw-  0 root   root     3003 May 28 06:35 var/lib/db/sbom/busybox-1.37.0-r41.spdx.json
-rw-rw-rw-  0 root   root     3397 May 28 06:35 var/lib/db/sbom/ca-certificates-bundle-20241121-r42.spdx.json
-rw-rw-rw-  0 root   root     3116 May 29 14:49 var/lib/db/sbom/cyrus-sasl-2.1.28-r42.spdx.json
-rw-rw-rw-  0 root   root     3093 May 28 06:35 var/lib/db/sbom/gdbm-1.25-r1.spdx.json
-rw-rw-rw-  0 root   root     3108 May 29 13:20 var/lib/db/sbom/gmp-6.3.0-r6.spdx.json
-rw-rw-rw-  0 root   root     2897 May 28 06:35 var/lib/db/sbom/isl-0.27-r1.spdx.json
-rw-rw-rw-  0 root   root     3319 May 28 06:35 var/lib/db/sbom/keyutils-libs-1.6.3-r32.spdx.json
-rw-rw-rw-  0 root   root     2046 May 28 06:35 var/lib/db/sbom/krb5-conf-1.0-r6.spdx.json
-rw-rw-rw-  0 root   root     3007 May 29 13:20 var/lib/db/sbom/krb5-libs-1.21.3-r42.spdx.json
-rw-rw-rw-  0 root   root     3028 May 28 06:35 var/lib/db/sbom/libbrotlicommon1-1.1.0-r5.spdx.json
-rw-rw-rw-  0 root   root     3007 May 28 06:35 var/lib/db/sbom/libbrotlidec1-1.1.0-r5.spdx.json
-rw-rw-rw-  0 root   root     3145 May 28 06:35 var/lib/db/sbom/libcom_err-1.47.2-r22.spdx.json
-rw-rw-rw-  0 root   root     3033 Jun  3 06:05 var/lib/db/sbom/libcurl-openssl4-8.14.0-r3.spdx.json
-rw-rw-rw-  0 root   root     3158 May 29 13:20 var/lib/db/sbom/libedit-3.1-r10.spdx.json
-rw-rw-rw-  0 root   root     3206 May 28 06:35 var/lib/db/sbom/libexpat1-2.7.1-r1.spdx.json
-rw-rw-rw-  0 root   root     3183 May 28 06:35 var/lib/db/sbom/libidn2-2.3.8-r1.spdx.json
-rw-rw-rw-  0 root   root     3269 May 29 02:02 var/lib/db/sbom/libldap-2.6.10-r2.spdx.json
-rw-rw-rw-  0 root   root     3033 May 28 06:35 var/lib/db/sbom/libnghttp2-14-1.65.0-r1.spdx.json
-rw-rw-rw-  0 root   root     3065 May 28 06:35 var/lib/db/sbom/libpcre2-8-0-10.45-r2.spdx.json
-rw-rw-rw-  0 root   root     2989 May 28 06:35 var/lib/db/sbom/libpsl-0.21.5-r5.spdx.json
-rw-rw-rw-  0 root   root     3253 May 28 06:35 var/lib/db/sbom/libunistring-1.3-r2.spdx.json
-rw-rw-rw-  0 root   root     2990 May 28 06:35 var/lib/db/sbom/libverto-0.3.2-r5.spdx.json
-rw-rw-rw-  0 root   root     3091 May 28 06:35 var/lib/db/sbom/libxcrypt-4.4.38-r2.spdx.json
-rw-rw-rw-  0 root   root     3119 May 28 06:35 var/lib/db/sbom/libxcrypt-dev-4.4.38-r2.spdx.json
-rw-rw-rw-  0 root   root     3010 May 28 06:35 var/lib/db/sbom/libzstd1-1.5.7-r2.spdx.json
-rw-rw-rw-  0 root   root     3106 May 28 06:35 var/lib/db/sbom/make-4.4.1-r5.spdx.json
-rw-rw-rw-  0 root   root     3074 May 28 06:35 var/lib/db/sbom/mpc-1.3.1-r6.spdx.json
-rw-rw-rw-  0 root   root     3097 May 28 06:35 var/lib/db/sbom/mpfr-4.2.2-r1.spdx.json
-rw-rw-rw-  0 root   root     3432 May 28 06:35 var/lib/db/sbom/ncurses-6.5_p20241228-r2.spdx.json
-rw-rw-rw-  0 root   root     3530 May 28 06:35 var/lib/db/sbom/ncurses-terminfo-base-6.5_p20241228-r2.spdx.json
-rw-rw-rw-  0 root   root     2238 May 28 06:35 var/lib/db/sbom/openssf-compiler-options-20240627-r20.spdx.json
-rw-rw-rw-  0 root   root     3000 May 28 06:35 var/lib/db/sbom/pkgconf-2.4.3-r2.spdx.json
-rw-rw-rw-  0 root   root     2114 May 28 06:35 var/lib/db/sbom/posix-cc-wrappers-1-r6.spdx.json
-rw-rw-rw-  0 root   root     3195 May 28 06:35 var/lib/db/sbom/readline-8.2.13-r4.spdx.json
-rw-rw-rw-  0 root   root     3196 May 29 09:22 var/lib/db/sbom/sqlite-libs-3.50.0-r0.spdx.json
-rw-r--r--  0 root   root     2151 Mar 31 06:08 var/lib/db/sbom/wolfi-baselayout-20230201-r20.spdx.json
-rw-rw-rw-  0 root   root     2950 May 28 06:35 var/lib/db/sbom/zlib-1.3.1-r7.spdx.json
```

Also, looking at the relative size of the overflow layer vs the layers that made the cut, it's not unreasonable:

```
$ crane manifest cgr.dev/chainguard/go@sha256:78036eb1e687715046b6f4850e9785355a58a88967ab2b853cfbfa46e245ee39 | jq '.layers[].size'
153505114
72330618
25702646
17118397
9087291
1916754
2778029
1413772
1117322
11134395
296522
```

Our overflow layer is about 10x the size of smallest package-ful layer, but still much smaller than the largest layers.
There are likely some small percentage improvement in deduplication we could attain here, but it's probably not worth the effort.

#### Top Layer

Finally, the top layer is any remaining files.
Which files are those?
Glad you asked.

As mentioned earlier, we track metadata about every file we lazily "write" to our references-to-tar-offsets-backed filesystem.
Part of that metadata is which package owned those file's bytes.
We use that ownership information to partition our single virtual filesystem into `$budget + 1` concrete layers.

Any file that has actual contents gets split out into its own layer (including directories that contain said file (see next section for more details)).
Any file _without_ package-owner metadata gets dumped into the top layer.

Primarily, this is a bunch of directories and device files, but the actually interesting files are OS metadata like the installed database.

Looking at `cgr.dev/chainguard/crane` and filtering out directories and files:

```
$ crane blob cgr.dev/chainguard/crane@sha256:5d26415966d404f314a45b7952a9b2e6f9a9fee1b535e8bebd123ff904111b74 | tar -tvz | grep -v -e '^d' | grep -v -e '^c'
-rw-r--r--  0 root   root        7 Dec 31  1969 etc/apk/arch
-rw-r--r--  0 root   root      800 Dec 31  1969 etc/apk/keys/wolfi-signing.rsa.pub
-rw-r--r--  0 root   root       30 Dec 31  1969 etc/apk/repositories
-rw-r--r--  0 root   root       82 Dec 31  1969 etc/apk/world
-r--r--r--  0 root   root      870 Dec 31  1969 etc/apko.json
lrwxrwxrwx  0 root    root        0 Mar 31 06:08 lib/apk -> ../usr/lib/apk
-rw-r--r--  0 root    root     2609 Dec 31  1969 usr/lib/apk/db/installed
-rw-------  0 root    root        0 Dec 31  1969 usr/lib/apk/db/lock
-rw-r--r--  0 root    root     1024 Dec 31  1969 usr/lib/apk/db/scripts.tar
-rw-r--r--  0 root    root        0 Dec 31  1969 usr/lib/apk/db/triggers
```

Again, these files were produced by the same code that apko has always used to generate single-layer images, so these should match what you'd expect.

## Results

Does this actually work in practice?

### Across Space

Let's look at two public images that should have a lot of overlap in their installed packages:

```
$ comm -12 \
    <(crane manifest --platform linux/amd64 cgr.dev/chainguard/gradle | jq '.layers[].digest' -r) \
    <(crane manifest --platform linux/amd64 cgr.dev/chainguard/jdk | jq '.layers[].digest' -r)
sha256:751aa1731700531822dd165e9b94f0d3557e6d9a3d479c1c67e24d3784340a3f
sha256:db70eed5a289b0f1d7a1ea36785a9dcbc0ef289a8663cc5a9ee8bc3320325e37
sha256:afc58e7b271e3e989292dea108da612444653f86f6f0745ad1699e80eaec9a08
sha256:2c87b77641e1f7762400a761f6190625a095011680971d9b86bd8f604046671e
sha256:fbb06e7d45863e8607250738faadf58352992f5f417e6764aafb2f47a2bb8e14
sha256:acaad7d4f229c940a3228d1170a02263374f7b640ccf9980f174b1ee8366164f
sha256:f96a4e40e9f1eb0df7d4bef81780ce0b6899ae9e7f3f707b3dd9f11e4ba27f53
sha256:e8f0a3361e4411faf5559c8f93113eeea0a7c6aa43bb01fb9172f5f744ab886c
```

The `jdk` and `gradle` images share most of their layers by count.
We get pretty decent sharing of layers across similar images.

## Across Time

How do we do with the same image as it changes over time?

Let's look at the counts of unique layers within the 10 most recent gradle images:

```
$ curl -s -H "$(crane auth token -H cgr.dev/chainguard/gradle)" https://cgr.dev/v2/chainguard/gradle/_chainguard/history/latest\?end\=3000-01-01T00%3A00%3A00.000Z \
  | jq '.history[].digest' -r | head -n 10 | xargs -n1 -I{} crane manifest --platform linux/amd64 cgr.dev/chainguard/gradle@{} \
  | jq '.layers[] | "\(.digest) \(.size)"' -r \
  | sort | uniq -c | sort -n
   1 sha256:0687e766052c4bb7acd662a60a48c5769e0673d83c14947007a6f3a63ca1fed1 2963776
   1 sha256:0b75aa176560094069142b4483ee28dd4e2760966c66ab70a40ae734847eadab 65185
   1 sha256:115facd2f2717ec3687b48c1e149bab61accb01c382438baa61569336f22a57c 64282
   1 sha256:1316b82f723d185c160f7897675f0878cc1ed9c9420a617b481f6196ea4d4edd 67266
   1 sha256:334129c24c3ee74a241c5b0610f43d0ef6ddde456425f8a05966c0eceeefce49 64272
   1 sha256:6a6db57cf22068bb3d3a82e53e4288d11ba84bdba967d844821943b53c4c54b6 2970485
   1 sha256:7b63427630312ac171847aa98e99690012cee264ff8a6a7256dd5665019e5432 65010
   1 sha256:90b11aebd3149d5e18ea925177b3026686e3d35dc5d411574fdf688cdfe8457a 65144
   1 sha256:9546f0ea3d8b5927a76ea1d7b83bdce40d2ed8750c6dbfa9b7e6ad25e997f111 64315
   1 sha256:96bb84bf6b678d2a4fc80ee09bdd621b2e754b7e4aa65a79106da17718561f13 2970499
   1 sha256:a722c03e5874bbc8ae7f7094785a3e07190d1a2ddce344ecb122e95d8c6e45d2 65149
   1 sha256:b3d19f90e8e4914ea70985b6547072ef6d5225fcf2e40a571efcd4f13ffd04ad 2970434
   1 sha256:b3e987c7cb25a7734de8b3f850dc0368f353428925a6305f04bcd9b363374d2c 65260
   1 sha256:cbfef2d4b60a33a02894df1eb84c861f81d6a224e0f9d814f3fe957172aa0e20 65070
   1 sha256:db70eed5a289b0f1d7a1ea36785a9dcbc0ef289a8663cc5a9ee8bc3320325e37 22293495
   1 sha256:ecc1cd11c33f8f9cb91792c9166601ee645fb6dc572157b1bba496079842bd3e 139912260
   2 sha256:0bd75a0ea92aa08986806061b19785c6c4d03794c09b7035dc4c9842d74d9b39 2965925
   2 sha256:1ec80df8f6be39f65d7ff3a16838b8ce82359f184a0bc9359a03847f171ac6ae 2966323
   2 sha256:6f57ef0b73246f856f3ecfd9442e1773bf185946765696cf9573f009dd2baf94 2966216
   3 sha256:f578aeb87d759ebd015dd05e91f69f89d0877a5c1e8155245e8425d251bbd114 22276588
   6 sha256:e572154e14b785d3aec83077dc343315da6fcd9f0d7c4950df94081025567a76 22260994
   9 sha256:ab7657aec6dad1a95cc8bcebd4c89a0f657877b32e6e00f106912ac02645d06c 139918243
  10 sha256:2c87b77641e1f7762400a761f6190625a095011680971d9b86bd8f604046671e 1838566
  10 sha256:751aa1731700531822dd165e9b94f0d3557e6d9a3d479c1c67e24d3784340a3f 97254522
  10 sha256:acaad7d4f229c940a3228d1170a02263374f7b640ccf9980f174b1ee8366164f 889941
  10 sha256:afc58e7b271e3e989292dea108da612444653f86f6f0745ad1699e80eaec9a08 10269539
  10 sha256:e8f0a3361e4411faf5559c8f93113eeea0a7c6aa43bb01fb9172f5f744ab886c 390729
  10 sha256:f96a4e40e9f1eb0df7d4bef81780ce0b6899ae9e7f3f707b3dd9f11e4ba27f53 674902
  10 sha256:fbb06e7d45863e8607250738faadf58352992f5f417e6764aafb2f47a2bb8e14 2286737
```

We see pretty decent overlap!
For the most part, the layers we see only once are very small (~64K), though there are a few larger ones that seem to change more frequently.
The layers we see with multiple times tend to be larger, which matches what our layering strategy is trying to achieve.

## Caveats

### Directory Timestamps

The initial implementation here produced results that didn't live up to what we expected.
After some investigation, we realized that our culprit was timestamps.

As mentioned in the "replaces" section, packages tend to have non-overlapping files.
This is true for regular files, but it doesn't apply to directories.
Packages almost always have overlapping directories!
And those directories almost always have different timestamps.

What does this mean for layering?
Cross-image deduplication won't work very well.

Even if all the files with actual contents were identical between two layers in different images, often the timestamps in directories were slightly different because of the order we "installed" other packages that belonged to different layers because of overlapping directories (this is a downside of our "install things the usual way then partition into separate layers" strategy that solved several other problems for us).

We really want that deduplication between images, so how could we solve this?

#### Option 1: Drop timestamps

If timestamps are a problem, just get rid of them!
Indeed, we used to do exactly this, but we ran into a number of applications that will `stat` certain files and refuse to start if their modtime was too old.
On top of that, timestamps are often useful for debugging things or for setting HTTP headers for caching, so we really wanted to keep them around.

Onto the next option.

#### Option 2: Drop directories

We don't _really_ need these directories in each layer, right?
We could just have those directories exist in the top layer and have orphaned files in our package-ful layers.

This would work, and it's not a terrible idea, but it relies on [implementation-defined behavior](https://github.com/opencontainers/image-spec/pull/970) of implicit directories and makes browsing individual layers cumbersome.

For now, we've rejected this option, but we might want to revisit it in the future.

#### Option 3: Synthesize Timestamps

Finally, we've come to the (current) hacky solution: https://github.com/chainguard-dev/apko/pull/1624

Instead of dropping directory timestamps in our layers, we just have parent directories adopt whatever timestamps their child files have.
These timestamps still get overwritten by the directory entry in the top layer, so semantically it's still identical to a single-layer image.
Since the timestamps are synthesized from files that _only_ exist in each layer, we don't have the unfortunate inter-layer influence that was invalidating our deduplication from before.

This has worked pretty well, but it may not be a permanent solution.

### Path Mutations

Another deduplication antagonist is apko's support for mutating [paths](apko_file.md#paths).
In particular, modifying the ownership or permissions of a file will affect layer contents and impact layer deduplication.
Unlike with directory timestamps, there's not much we can do here to fix it.

Because layers are tarballs, there's no cheap mechanism to overwrite _just_ file metadata in the top layer.
We'd have to overwrite the entire thing, which doesn't feel worth doing.

Luckily, these kinds of path mutations aren't that common, just be aware that modifying permissions of a file in one image may mean it won't see any deduplication with similar layers in other images without said modifications.

### usr/lib/apk/db/installed

In order to associate files with packages, security scanners look at `usr/lib/apk/db/installed` (or "idb" for _installed database_).
We've run into some scanners that look at each layer individually rather than the entire filesystem.
For those scanners, having all of our operating system metadata files (including this idb file) in the top layer violated some of their assumptions around valid layers.
In order to avoid breaking those scanners, we duplicate relevant portions of the idb file in each package-ful layer.
These files are small relative to the size of most packages, so it doesn't cost much to do this for broader compatibility with security scanners.
