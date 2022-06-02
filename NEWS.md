# Changes from 0.3.3 to 0.4.0

* Allow the apk installed DB to be attached as an "IDB" SBOM.
  This can be used for scanning a runtime container for deviations
  with the `apk audit` command.

* The Tekton apko task is now automatically generated as part of
  the release process.

* Creation times for SPDX SBOMs are now determined from the
  `SOURCE_DATE_EPOCH` environment variable for consistency with
  other artifacts (such as the image filesystem modification times).

* OCI mediatypes are now used by default instead of the Docker ones.
  If you want to use Docker mediatypes (e.g. for quay.io), you can
  use the `--use-docker-mediatypes` option.

* A new `show-config` applet has been added to show all of the
  configuration for an image that was derived from loading a YAML
  file.

* The CLI commands are no longer exported for public consumption
  from other projects.

# Changes from 0.3.2 to 0.3.3

* Ensure home directories are created with 0755 permissions.

# Changes from 0.3.1 to 0.3.2

* Ensure all home directories for accounts in `/etc/passwd` are present
  and have the correct permissions.

# Changes from 0.3.0 to 0.3.1

* Allow `entrypoint` to be blank.

* Add new `cmd` statement to the YAML configuration.

* Generate `/etc/alpine-release` (or equivalent) legacy files when
  `/etc/os-release` generation is requested.  This helps with Trivy
  scanning.

# Changes from 0.2.2 to 0.3.0

* Significantly improved documentation.

* Add support for generating `/etc/os-release` files for scanner
  compatibility.

* Fix specification of architectures in apko YAML configuration
  files.

* Add support for doing various path mutations on an image,
  like changing the owner of a file or its permissions.

* Attach SBOMs to built images.

* Use pargzip to compress images for speed.

* Improve test coverage by refactoring the code to allow for
  mock implementations.

* Properly track hardlinks when generating a layer tarball.

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

