# Contributing

> Thank you for you interest in apko!  You are welcome here.

apko and [melange](https://github.com/chainguard-dev/melange) are open
source projects, always open for outside contributors.

If you are looking for a place to start take a look at the 
[open issues](https://github.com/chainguard-dev/apko/issues), 
especially those marked with
[good-first-issue](https://github.com/chainguard-dev/apko/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22).

## Setting Up a Development Environment

Running apko requires an environment with apk available. To make development 
easier under any platform, we have created a script that uses apko itself to
bootstrap a development environment under any platform with docker installed.

To run it, simply execute the following script from the top of the apko
repository:

```shell
./hack/make-devenv.sh
```

That command should use apko to create a development image with some 
useful tools. It will load the devel image into your local docker daemon and
drop you into a shell. The apko repository in your local machine will be 
mounted in the current working directory.

You can use your editor to change the apko code and execute apko in the
development shell to test it out:

```shell
$ go run ./main.go
Usage:
  apko [command]

Available Commands:
  build            Build an image from a YAML configuration file
  build-minirootfs Build a minirootfs image from a YAML configuration file
  clean            Clean the apko cache directory
  completion       Generate the autocompletion script for the specified shell
  dot              Output a digraph showing the resolved dependencies of an apko config
  help             Help about any command
  install-keys     Discover and install keys for all repositories
  login            Log in to a registry
  publish          Build and publish an image
  show-config      Show the configuration derived from loading a YAML file
  show-packages    Show the packages and versions that would be installed by a configuration
  version          Prints the version

Flags:
  -h, --help               help for apko
      --log-level string   log level (e.g. debug, info, warn, error, fatal, panic) (default "INFO")
  -C, --workdir string     working dir (default is current dir where executed) (default "/Users/marco/code/priv/apko")

Use "apko [command] --help" for more information about a command.
$ go run ./main.go version
     _      ____    _  __   ___
    / \    |  _ \  | |/ /  / _ \
   / _ \   | |_) | | ' /  | | | |
  / ___ \  |  __/  | . \  | |_| |
 /_/   \_\ |_|     |_|\_\  \___/
apko

GitVersion:    devel
GitCommit:     unknown
GitTreeState:  unknown
BuildDate:     unknown
GoVersion:     go1.24.6
Compiler:      gc
Platform:      linux/amd64
```

When done developing, simply exit the development shell. We would love to hear
about your experience in the development shell and any ideas you may have!

## Linting and Tests

Before submitting a pull request, make sure tests and lints do not complain.
Make sure you have go 1.24 or newer and
[golangci-lint](https://golangci-lint.run/welcome/install/) installed (make task takes care of installing) and try
running the linter and tests:

```shell
make fmt lint 
make test
```
