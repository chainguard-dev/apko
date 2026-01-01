# apko-as-apk

`apko-as-apk` is an APK-compatible package manager that uses apko's existing functionality to provide a drop-in replacement for common `apk` commands.

## Overview

This binary leverages the extensive APK package management capabilities already built into apko, allowing it to operate directly on filesystem trees (including the root filesystem) rather than just building container images.

## Building

```bash
make apko-as-apk
```

This creates a statically-linked binary (~27MB) in the project root.

## Usage

The tool is designed as a drop-in replacement for `apk` with compatible command-line flags:

```bash
# By default, operates on root filesystem (/)
apko-as-apk [command] [flags]

# Operate on an alternate root
apko-as-apk --root /path/to/root [command] [flags]
```

## Implemented Commands

### info
Display information about installed packages.

```bash
# List all installed packages
apko-as-apk info

# List with versions
apko-as-apk info -v

# Show package details
apko-as-apk info busybox

# Show package contents
apko-as-apk info -L busybox

# Show dependencies
apko-as-apk info -R busybox

# Show all information
apko-as-apk info -a busybox
```

**Status**: ✅ Fully functional

### update
Update repository indexes from configured repositories.

```bash
apko-as-apk update
```

**Status**: ✅ Fully functional

### add
Add packages and their dependencies to the system.

```bash
# Add a package
apko-as-apk add curl

# Initialize database and add package
apko-as-apk add --initdb curl

# Simulate without making changes
apko-as-apk add --simulate curl
```

**Status**: ⚠️ Partially functional

**Known Issue**: The `add` command currently has issues installing packages that contain install scripts. The command successfully:
- Resolves dependencies correctly
- Downloads packages
- Reads package metadata

However, it fails during installation for packages with install scripts with an error:
```
unable to update scripts.tar for pkg: unable to stat scripts file: file does not exist
```

This appears to be related to how apko's package installation code handles script extraction and would require further investigation into the `pkg/apk/apk/install.go` implementation.

**Workaround**: The native `apk` command can still be used for package installation, while `apko-as-apk info` and `apko-as-apk update` work correctly alongside it.

## Global Flags

The tool supports the same global flags as `apk`:

- `-p, --root ROOT` - Manage file system at ROOT (default: `/`)
- `-v, --verbose` - Print more information (can be specified twice)
- `-q, --quiet` - Print less information
- `-X, --repository REPO` - Specify additional package repository
- `--arch ARCH` - Temporarily override architecture
- `--cache-dir DIR` - Override the cache directory
- `--allow-untrusted` - Install packages with untrusted signatures
- `--no-cache` - Do not use any local cache
- `--keys-dir DIR` - Override directory of trusted keys
- And more...

## Architecture

The implementation reuses apko's existing code:
- **`pkg/apk/apk`** - Complete APK package management implementation
- **`pkg/apk/fs`** - Filesystem abstraction supporting real filesystems
- **`internal/cli/apkcompat`** - New CLI interface matching `apk` command structure

No new APK parsing or installation code was needed - everything leverages battle-tested apko functionality.

## Design Decisions

1. **Default to root=/**: Unlike apko's image building mode, this tool defaults to operating on the live system root (`/`), matching `apk` behavior.

2. **Reuse existing code**: The implementation deliberately reuses apko's `pkg/apk/apk` package rather than reimplementing APK operations.

3. **Compatible interface**: Command-line flags and output formats match `apk` where possible for familiarity.

## Testing

### Unit Tests

Run fast unit tests that don't require Docker:

```bash
make test-apko-as-apk
```

These tests cover:
- Repository file parsing
- Key installation logic
- Package info formatting
- Helper functions

### Container Integration Tests

Run integration tests that compare `apk` and `apko-as-apk` behavior in Docker containers:

```bash
make test-apko-as-apk-container
```

**Note**: Requires Docker to be running.

These tests:
- Compare `info` command output between `apk` and `apko-as-apk`
- Verify `update` command updates repository indexes correctly
- Test various command-line flags and options
- Validate exit codes and error handling

Tests use the `containerTest` build tag and can also be run directly:

```bash
go test -tags containerTest ./internal/cli/apkcompat/... -v
```

### Manual Testing

Test in a container interactively:

```bash
# Start container with binary mounted
docker run --rm -it \
  --mount=type=bind,source=$PWD/apko-as-apk,destination=/usr/bin/apko-as-apk \
  cgr.dev/chainguard/wolfi-base:latest \
  sh

# Inside container, compare commands:
apk info
apko-as-apk info

apk info -v
apko-as-apk info -v

apk info busybox
apko-as-apk info busybox
```

## Future Work

- **Fix install script handling**: Investigate and resolve the script extraction issue in package installation
- **Add more commands**: Implement additional `apk` subcommands (del, upgrade, fix, etc.)
- **Add tests**: Create Go tests with `containerTest` build tag for integration testing
- **Improve output formatting**: Match `apk` output more precisely in edge cases
- **Virtual packages**: Implement support for the `--virtual` flag in `add` command
