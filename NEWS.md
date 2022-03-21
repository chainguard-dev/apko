# Changes from 0.2.1 to 0.2.2

* Added `apko login` as alternative to `docker login`.

* Fixes for logging in "early" build contexts for paths outside
  `apko publish`.

* Provide a default environment for the image configuration.

* Set the `mediaType` on OCI indexes when publishing so that
  `ko` can use them correctly.

# Changes from 0.2.0 to 0.2.1

* Minor brown-paper-bag fix for multitagging.

# Changes from 0.1.2 to 0.2.0

* New option `--use-proot` for rootless image builds.

* Support for multi-arch builds in `apko publish`, this requires
  the qemu emulators to be installed.  If you do not want to use
  qemu emulation, then use the `--arch` option to do a single
  architecture build.

* Added `--keyring-append` and `--repositories-append` options.

* Added management of UIDs and GIDs, for an example of how to use
  this functionality, see the `examples/alpine-base-rootless.yaml`
  file.

* Added support for multiple tags in `apko publish`.

# Changes from 0.1.1 to 0.1.2

* Minor bugfix for usage scenario involving the APK system
  keyring.

# Changes from 0.1 to 0.1.1

* Build system refactoring c/o Jason Hall and Carlos Panato

* Support for copying the APK system keyring if no explicit
  keyring is configured, c/o Adolfo García Veytia (Puerco)

* Support for outputting the image digest, allowing it to
  be used as an input for `ko build` c/o Jason Hall

