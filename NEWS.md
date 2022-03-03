# Changes from 0.1.2 to ???

* New option `--use-proot` for rootless image builds.

# Changes from 0.1.1 to 0.1.2

* Minor bugfix for usage scenario involving the APK system
  keyring.

# Changes from 0.1 to 0.1.1

* Build system refactoring c/o Jason Hall and Carlos Panato

* Support for copying the APK system keyring if no explicit
  keyring is configured, c/o Adolfo García Veytia (Puerco)

* Support for outputting the image digest, allowing it to
  be used as an input for `ko build` c/o Jason Hall

