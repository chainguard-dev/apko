# Apko Release Process

## Patch releases

The most common type of release of Apko is a patch release. Generally we should aim to do these as often as necessary to release _backward compatible_ changes, especially to release updated dependencies to fix vulnerabilities.

To cut a release:
- go to https://github.com/chainguard-dev/apko/releases/new
- click "Choose a tag" then "Find or create a new tag"
- type a new patch version tag for the latest minor version
  - for example, if the latest version is `v0.11.5`, create a patch release `v0.11.6`
- click "Create new tag: v0.X.Y on publish"
  - you can leave the release title empty
- click "Generate release notes"
  - make any editorial changes to the release notes you think are relevant
- make sure "Set as the latest release" is checked
- click **"Publish release"**

### Monitor the release automation

Once the tag is pushed, the [`Create Release` action](https://github.com/chainguard-dev/apko/actions/workflows/release.yaml)
will attach the appropriate release artifacts and update release notes.

At the time of this writing, the release job takes 20 to 30 minutes to execute.

Make any editorial changes to the release notes you think are necessary.
You may want to highlight certain changes or remove items that aren't interesting.

Once the `Release` action has been completed successfully, find your release on
the [releases page](https://github.com/chainguard-dev/apko/releases)

### Update dependents

Apko is used as a library in [Melange](https://github.com/chainguard-dev/melange), [`wolfictl`](https://wolfi.dev/wolifctl), and [`terraform-provider-apko`](https://github.com/chainguard-dev/terraform-provider-apko), among others.

When you cut a release of Apko, particularly when it's to update a vulnerable dependency, you'll probably also want to pick up those changes in Apko's dependents.

## Minor releases

Occasionally there are large or breaking changes to Apko that we want to highlight with a new minor release.
A minor release should be cut shortly after a breaking change is made, so that regular patch releases don't release breaking changes.

The process for cutting a release is exactly the same as above, except that you should pick a new minor version.

For example, if the latest version is `v0.11.5`, create a minor release `v0.12.0`.

### Release [`terraform-provider-apko`](https://github.com/chainguard-dev/terraform-provider-apko)

For consistency, we prefer to keep minor releases of Apko in-line with minor releases of the Terraform provider.

This means that when you cut `v0.12.0`, we should also cut a release of tf-apko to `v0.12.0`.

We don't bother trying to keep patch releases in-sync between these repos, so you don't have to do this on every new patch release.
