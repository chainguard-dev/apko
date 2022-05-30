# Frequently Asked Questions (FAQ)

Some questions that have come up about `apko`.

## Is it a valid use case to build on top of apko generated images with other tooling e.g. Dockerfiles?

Yes!

We encourage people to use `apko` and `melange` to build their own images, but in some cases
existing or alternative tooling will be more appropriate.

If you want to add files or packages outside of APK artifacts on top of an `apko` generated base
image, then using Dockerfiles or similar is definitely a supported use case. `apko` aims to
enable people to use the patterns that suit them and their workflow best.

Having said that, we believe using APK to install everything offers big advantages with regards
to compliance and auditability - there will be SBOMs for all the contents and security scanners
will be aware of all installed software.

## Can we use `apko` as a library?

Making an `apko` library isn't a current priority, but we would welcome patches towards this
goal.

If you want to wrap the CLI, note that breaking changes are possible, but will be announced in
`NEWS.md`.
