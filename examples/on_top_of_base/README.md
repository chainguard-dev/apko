## Overview

This example demnostrates the possibility to build with APKO on top of base image. 

**WARNING** Still work in progress, subject to breaking API change.

**Current limitations**

* Base image must be present on the filesystem
* Build requires a lockfile
* The config may only add packages. Other top level elements are banned.
* SBOM generation is incomplete - omits any contents of the base image.

## How to use

Currently the functionality requires the base image and it's metadata to be present on the filesystem. 

For the `apko.yaml` example, do the following steps:

1. Go the `apko.yaml's` directory
2. Download base image and prepare metadata

```
./prepare_base.sh
```

3. Create lock

```
apko lock apko.yaml  
```

4. Create output directory

```
mkdir top_image
```

4. Build the image

```
apko build apko.yaml dev:latest top_image/ --lockfile=apko.lock.json --sbom=False
```
