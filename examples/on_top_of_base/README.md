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

1. Go the apko repository root directory
2. Run 

```
./examples/on_top_of_base/build.sh
```

It optionally accepts the apko binary as first argument. By default it will use apko from PATH.