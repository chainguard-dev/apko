# SBOM Composition

apko generates a Software Bill of Materials (SBOM) describing the container
images it builds, it has total visibility into all system packages it pulls to
assemble the images. This visibility means that the generated SBOMs have
complete coverage of all OS packages used, but apko does not build the packages 
it uses, it only installs them. 

As it tried to be a responsible SBOM citizen, apko will not try to "guess" data 
from the apk packages used to create container images. A great SBOM needs to 
include data like language dependencies, build tools, source code information, 
etc, but trying to extract - or worse, infer - that data from apko's point of 
view is not a good practice.

Instead, apko was designed to be a strong link in the software supply chain by 
leveraging data produced by distributed, trusted processes.  To create a richer 
SBOM, apko can read and incorporate data included in SBOMs it finds inside the 
signed apks used to assemble images.

If tools downstream package SBOMs with the data they have visible (for example 
when compiling software), apko can read those SBOMs and augment its own bills of
 materials, resulting in more complete documents with data generated at the 
 source.

For apko to consider SBOMs stored in apk packages, they need to meet specific 
criteria.

## Conditions For SBOM Package Composition

To consider SBOMs stored inside of apks, apko needs to be able to:

* Find the internal SBOM
* Ensure the document contains data about the packages it uses to build the 
container image.

The first item is achieved with naming and path conventions, and the second by 
matching information inside the internal SBOM.

When building a container image, apko will generate an SPDX package describing 
each of the apks it uses to build it. These SBOMs have the following structure '
(simplified example):

```
 📂 SPDX Document sbom-sha256:cf796cb59ee882685c0dc6b828d2310f4504f5af00277a96db62be1b62f3a036
  │ 
  │ 📦 DESCRIBES 1 Packages
  │ 
  └ sha256:73226d804e1666c4f251ec4b34d9ee2aa6d2c8014fb517e13cf5ccf7d579f486
     │ 🔗 2 Relationships
     └ CONTAINS PACKAGE sha256:cf796cb59ee882685c0dc6b828d2310f4504f5af00277a96db62be1b62f3a036
        │ 🔗 2 Relationships
        ├ CONTAINS PACKAGE busybox
        └ CONTAINS PACKAGE kubectl

```

The baseline data in each of these packages is limited to what the apk system 
can provide to apko: name, version, checksum, license, and other metadata about 
the apk package itself. apk will not provide information about language 
dependencies, build tooling, etc. But, if the apk itself includes an SBOM with 
additional data apko will happily use it.

After augmentation, apko can provide more complete SBOMs that add the data in 
the internal documents to generate an SBOM closer to the following structure:

```
 📂 SPDX Document sbom-sha256:cf796cb59ee882685c0dc6b828d2310f4504f5af00277a96db62be1b62f3a036
  │ 
  │ 📦 DESCRIBES 1 Packages
  │ 
  └ sha256:73226d804e1666c4f251ec4b34d9ee2aa6d2c8014fb517e13cf5ccf7d579f486
     │ 🔗 2 Relationships
     └ CONTAINS PACKAGE sha256:cf796cb59ee882685c0dc6b828d2310f4504f5af00277a96db62be1b62f3a036
        │ 🔗 2 Relationships
        ├ CONTAINS PACKAGE busybox
        │  │ 🔗 2 Relationships
        │  ├ CONTAINS FILE /bin/busybox (/bin/busybox)
        │  └ CONTAINS FILE /etc/securetty (/etc/securetty)
        │ 
        └ CONTAINS PACKAGE kubectl
           │ 🔗 1 Relationships
           │ CONTAINS FILE /usr/bin/kubectl (/usr/bin/kubectl)
           └ GENERATED_FROM DocumentRef-kubernetes-v1.23.1 (external)
```

### Finding internal SBOMs

To find an apk SBOM,  apko will look for SPDX files stored inside of 
`/var/lib/db/sbom/` in the apk filesystem. The name of the file needs to meet 
the following convention:

```
   packageName-version-epoch.spdx.json
```

For example, GNU `hello` version 2.2 (epoch 0) would be stored in the file 
`/var/lib/db/sbom/hello-2.12-r0.spdx.json` in the apk filesystem. As you can 
guess from the name, apko supports SBOMs in SPDX version 2.2 and 2.3 encoded in 
JSON.

apko will look for SBOMs in the following alternative paths:

```
   /var/lib/db/sbom/packageName-version-epoch.spdx.json
   /var/lib/db/sbom/packageName-version.spdx.json
   /var/lib/db/sbom/packageName.spdx.json
```
It is not recommended to use the last two path schemas in automated 
environments, they are meant to support manually generated SBOMs when a project 
requires it.

###  Package Data in apk SBOMs

After finding an SBOM in an APK, apko will look inside it to read additional 
data about the package. Apko will incorporate the data expressed by the internal 
SBOM provided that the following conditions are met:

The apk is described in an element at the top level of the SBOM
The SPDX package `name` field must match the apk name
The SPDX package `versionInfo` field must match the apk version, a dash, an "r" 
character plus the epoch digits.

For example, if apko installs an apk for busybox version 1.35.0 (epoch 28) when 
building an image, a package needs to specify its `name` and `versionInfo` as:

```json
      "name": "busybox",
      "versionInfo": "1.35.0-r28",
```

If `name` is anything else, or `versionInfo` doesn't match the version + epoch 
pattern, apko will not use the SPDX package data.

## Composing Mechanics

The ultimate goal when composing data from SBOMs found in apks is to obtain a 
data-rich package with information from all tools. Any packages found in the apk 
SBOMs will be considered cannon and will replace the equivalent generated at the 
image level. All data provided at the image level from the packaging system will 
be used to augment it (this may not be the case yet, see Limitations, above).

apko will follow the imported SPDX package's relationship graph and compose all 
related elements into the image SBOM. Graph traversal ensures that apko gets all 
the richness available at previous stages in the build process. For more 
information about how SPDX relates elements see [_Relationships between SPDX 
elements_](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/) 
in the spec. See also the Limitations sections below.

## Limitations

This following are known limitations of the composing system. Issues are linked
where applicable to track their evolution.

* As of this writing, [apko will replace the SPDX package in the image SBOM](https://github.com/chainguard-dev/apko/issues/439) 
with the one found inside the apk document. We are working on smarter composing 
as we want to keep data from both packages.

* There is currently no way to [stop the traversal of the dependency graph](https://github.com/chainguard-dev/apko/issues/438) 
or [limit the relationships considered](https://github.com/chainguard-dev/apko/issues/437). 
apko will follow all relationships starting from the package it wants to import 
until it exhausts all paths. This means that apko can potentially import the 
complete SBOM. To work around this limitation, ensure your SBOM is scoped to 
only the package you want to see composed into the image SBOM.
