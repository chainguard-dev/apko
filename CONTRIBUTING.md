# Contributing

### Thank you for you interest in apko!  You are welcome here.

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

```bash
./hack/make-devenv.sh
```

That command should use apko to create a development image with some 
useful tools. It will load the devel image into your local docker daemon and
drop you into a shell. The apko repository in your local machine will be 
mounted in the current working directory.

You can use your editor to change the apko code and execute apko in the
development shell to test it out:

```
go run ./main.go

e5cf7d79f68b:/apko# go run ./main.go version
     _      ____    _  __   ___
    / \    |  _ \  | |/ /  / _ \
   / _ \   | |_) | | ' /  | | | |
  / ___ \  |  __/  | . \  | |_| |
 /_/   \_\ |_|     |_|\_\  \___/
apko

GitVersion:    
GitCommit:     unknown
GitTreeState:  unknown
BuildDate:     unknown
GoVersion:     go1.18
Compiler:      gc
Platform:      linux/amd64


```

When done developing, simply exit the development shell. We would love to hear
about your experience in the development shell and any ideas you may have!

## Linting and Tests

Before submitting a pull request, make sure tests and lints do not complain. 
Make sure you have go 1.18 and
[golangci-lint](https://golangci-lint.run/usage/install/) installed and try
running the linter and tests:

```
go test ./...
golangci-lint run
```
