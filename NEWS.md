# Changes from 0.12.0 to 0.13.0

* Add `apko build --lockfile` flag that makes the build use strict versions from the file
* Add `apko lock`: https://github.com/chainguard-dev/apko/pull/979
* Add per-package `checksum` field to the lockfile.
* Deprecate `apko resolve` (please use `apko lock` instead).

# Changes from 0.11.3 to 0.12.0

* Fix installing packages with multiple replaces.
* Fix files paths within SBOMs.

# Changes from 0.11.2 to 0.11.3

* Build with go 1.21.
* Remove unused flags:
  * `--use-docker-mediatypes`
  * `--package-version-tag`
  * `--package-version-tag-stem`
  * `--package-version-tag-prefix`
  * `--tag-suffix`
  * `--stage-tags`

# Changes from 0.11.1 to 0.11.2

* Fix a bug in version selection.

# Changes from 0.11.0 to 0.11.1

* Add JSON tags to ImageConfiguration types: https://github.com/chainguard-dev/apko/pull/933

* Pass UID and GID mapping to the tarball writer: https://github.com/chainguard-dev/apko/pull/932

Full diff: https://github.com/chainguard-dev/apko/compare/v0.11.0..v0.11.1

# Changes from 0.10.0 to 0.11.0

* Improve error messages when modifying paths.

* Optimize SBOM generation.

* Add `apko dot`: https://github.com/chainguard-dev/apko/pull/894

* Add hidden `apko resolve`: https://github.com/chainguard-dev/apko/pull/902

* Allow writing to OCI layout directory: https://github.com/chainguard-dev/apko/pull/882

* Add `--offline` flag: https://github.com/chainguard-dev/apko/pull/860

* Performance improvements and bug fixes

Full diff: https://github.com/chainguard-dev/apko/compare/v0.10.0..main

# Changes from 0.9.0 to 0.10.0

* Fix `--package-version-flag`.

* Fix `--workdir` flag.

* Switch from `pargzip` to `pgzip` for more efficient and faster compression.

* Improve caching to speed up repeated installs of the same APKs.

* Various small performance improvements.

* Add OpenTelemetry spans for debugging performance issues.

# Changes from 0.8.0 to 0.9.0

* Use external `go-apk` library instead of internal APK implementation.

* Retry fetching packages on failure.

* Deprecate configured build options in favor of the `--extra-packages`
  command line option.

* Compute build timestamps from latest installed APK if `SOURCE_DATE_EPOCH`
  is unset.

* Stop fetching Alpine keyring for non-Alpine distributions.

* Cache fetched APKs which have been downloaded from configured repositories.

# Changes from 0.7.3 to 0.8.0

* Add support for fuzzy version matching using the tilde operator (`~`).
  This is necessary to support Python packages in Alpine 3.18 or later, which
  declare a dependency on the versioned Python runtime.

* Implement `--log-policy` which allows users to specify logging policies,
  such as `--log-policy builtin:stderr,/home/build/buildlogs/foo.log`.  This
  logging policy would cause log data to be written to `stderr`, as well as
  `/home/build/buildlogs/foo.log`.

* Send `user-agent` in HTTP requests.

* Add support for using `/etc/busybox-links.d` files to set up the BusyBox
  symlinks where present, instead of using hardcoded lists.

* Add support for configuring the signal used by an OCI runtime to stop
  processes in a container.

* Ensure files are truncated when installing new files which replace files
  from other packages.

# Changes from 0.7.2 to 0.7.3

* Fix recording symlinks when operating on a case-insensitive filesystem.

* Improve `busybox --install -s` emulation.

* Fix permissions of created home directories.

* Fix regression in generated SBOMs where individual files in the image
  were not included, only the top-level packages.

# Changes from 0.7.1 to 0.7.2

* BusyBox: ensure a symlink for `tree` is installed.  This was a new
  applet added in BusyBox 1.36.

* Various regression fixes regarding the native apk implementation in
  apko.

# Changes from 0.7.0 to 0.7.1

* Fix an issue where the user-requested tag was not being used for
  locally built images with the `apko build` command.  Now, multi-arch
  images built with `apko build` will use the user-requested tag
  appended with the architecture the image is for.  This is due to a
  limitation in Docker.

* Fix a regression where the `/bin/find` symlink to BusyBox was not
  properly installed.

# Changes from 0.6.0 to 0.7.0

* `apk-tools` is no longer required to build images, instead a native
  implementation has been integrated as a replacement.

* The alpine keyring is no longer required to build images for Alpine.
  Instead, keys are downloaded from Alpine's website as required.

* The `--stage-tags` option has been added to allow postponing image
  tagging until after acceptance tests are run.

* Index SBOMs are now always generated, even for single-arch images.

* SBOMs from APK packages are now integrated into the image-level
  SBOM.

# Changes from 0.5.0 to 0.6.0

* Environment variables in the image configuration are now sorted
  for reproducibility.

* Tags can now be automatically generated based on a specified
  package's version.  The tags will be stemmed if this feature is
  used.

* Support for tracking individual files in SBOMs has been added for
  SPDX SBOMs.

* SPDX SBOMs generated with apko are now compliant with the SPDX 2.3
  specification.

* Support for glibc-based images has been added, such as configuring
  the dynamic linker cache via `ldconfig`.  This is needed for building
  images for Wolfi.

* Apko no longer clobbers `/etc/os-release` if it is already present,
  unless an override is explicitly requested.

* Support for adding suffixes to tags when publishing has been added
  via the `--tag-suffix` option.

* When using `proot`, apko no longer tries to `chown` or `chmod`
  anything.

* Support for publishing to the local Docker daemon has been added
  via the `--local` option.

# Changes from 0.4.0 to 0.5.0

* Add support for including base configuration with the `include`
  property.  These includes can reference a local file or a remote
  file hosted on a git forge.

* Add support for declaring custom OCI annotations.  These
  annotations can be provided on the command line or added to
  the YAML configuration.

* Index SBOMs are now created for multi-arch images.

* Many quality improvements in the SBOMs generated by apko, for
  example, PUrls are now correctly generated for OCI images.

* Account names specified in `run-as` are now mapped to UIDs at
  image creation time.

* Source repositories where apko configuration files live are now
  included as the org.opencontainers.image.source annotation.
  Users may build with `--vcs=false` to disable this feature or
  explicitly set the `vcs-url:` property in the YAML configuration.

* Permissions on the `s6` supervision tree are fixed for rootless
  images.

* Logging infrastructure has been changed to Logrus.

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

