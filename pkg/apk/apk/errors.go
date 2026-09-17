// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apk

import (
	"errors"
	"fmt"
	"strings"

	"chainguard.dev/apko/pkg/apk/types"
)

type FileExistsError struct {
	Path string
	Sha1 []byte
}

func (f FileExistsError) Error() string {
	return fmt.Sprintf("file %s already exists", f.Path)
}

func (f FileExistsError) Is(target error) bool {
	var targetError FileExistsError
	return errors.As(target, &targetError)
}

// FileConflictError is returned when a file has conflicting origins.
//
// Generally, this is a user Config error. However, since this can happen
// both during Config resolution, and building - it is hard for users using
// chainguard.dev/apko as a library to flag this to the user as a user error.
//
// To help with that, we create this structure error.
type FileConflictError struct {
	// The full path of the file that has conflicting origins.
	Path string

	// The origins of the file, as a map from the package name to the origin
	Origins map[string]string
}

func (f FileConflictError) Error() string {
	return fmt.Sprintf("packages %v has conflicting file: %q", f.Origins, f.Path)
}

func (f FileConflictError) Is(target error) bool {
	var targetError FileConflictError
	return errors.As(target, &targetError)
}

// Reasons a package's data is refused. These are matchable with errors.Is, so
// a caller can distinguish the cases without parsing message text.
var (
	// ErrEmptyName is returned when an archive entry name is empty. Such a name
	// has no valid representation on disk, and it previously reached an
	// unguarded index into its first byte.
	ErrEmptyName = errors.New("name is empty")

	// ErrControlCharacter is returned when an archive entry name contains a
	// byte below 0x20 or the DEL byte 0x7f.
	ErrControlCharacter = errors.New("name contains a control character")

	// ErrEmbeddedNewline is returned when a value would be written into a
	// line-oriented database as more than one line.
	//
	// This is an alias for types.ErrEmbeddedNewline rather than a second
	// sentinel with the same meaning. The .PKGINFO parser rejects the same
	// class of value one layer earlier, and a caller matching only one of two
	// look-alike sentinels would silently miss half the cases -- which is the
	// coupling these sentinels exist to remove, not to reintroduce across a
	// package boundary.
	ErrEmbeddedNewline = types.ErrEmbeddedNewline

	// ErrInstallAborted is returned by any install or record write attempted
	// after an earlier package install failed. It always wraps the original
	// failure, so a caller can match this to mean "this instance is finished"
	// while still recovering the cause with errors.As.
	ErrInstallAborted = errors.New("refusing to continue after an earlier package install failed")
)

// InvalidFieldError is re-exported so that a caller which matched
// ErrEmbeddedNewline through this package can also recover the offending
// .PKGINFO field and value through it, rather than having to import
// pkg/apk/types for the error type after importing nothing else from it. This
// package already aliases PackageInfo and Package for the same reason.
type InvalidFieldError = types.InvalidFieldError

// InvalidEntryNameError is returned when an archive entry name cannot be used.
//
// The apk installed database is a newline-delimited "<token>:<value>" format
// written from these names verbatim, so a control character -- a newline in
// particular -- would let a package forge additional records. Like
// FileConflictError, this is surfaced as its own type so that library consumers
// such as melange can report a malformed or malicious package as a package
// problem rather than an opaque build failure.
//
// Use errors.As to recover the package and path, and errors.Is against
// ErrEmptyName, ErrControlCharacter or ErrEmbeddedNewline to distinguish the
// reason.
type InvalidEntryNameError struct {
	// Package is the name of the package the entry came from.
	Package string

	// Path is the offending entry name.
	Path string

	// Err is why the name was rejected: ErrEmptyName or ErrControlCharacter from
	// the install paths, or ErrEmbeddedNewline from the installed-database sink.
	Err error
}

func (e InvalidEntryNameError) Error() string {
	return fmt.Sprintf("package %q: refusing to handle archive entry name (%v): %q",
		types.TruncateForError(e.Package), e.Err, types.TruncateForError(e.Path))
}

func (e InvalidEntryNameError) Unwrap() error { return e.Err }

// MalformedPackageError is returned when a package's own data, rather than one
// of its file names, would produce an installed-database record that is unsafe
// or unreadable.
//
// Use errors.As to recover the field and value, and errors.Is against
// ErrEmptyName or ErrEmbeddedNewline for the reason.
type MalformedPackageError struct {
	// Package is the name of the offending package. Empty when the package name
	// is itself what was rejected.
	Package string

	// Field identifies what was wrong: "name" for the package name, or the
	// installed-database token of the offending record line, e.g. "T:".
	Field string

	// Value is the offending value.
	Value string

	// Err is why it was rejected: ErrEmptyName or ErrEmbeddedNewline.
	Err error
}

func (e MalformedPackageError) Error() string {
	// %q on Field as well as Value. Field is internally generated today, but the
	// type is exported and a caller can construct one, and an unescaped newline
	// here would forge log lines from the very input this error exists to reject.
	return fmt.Sprintf("package %q: refusing to write installed-database %q (%v): %q",
		types.TruncateForError(e.Package), types.TruncateForError(e.Field),
		e.Err, types.TruncateForError(e.Value))
}

func (e MalformedPackageError) Unwrap() error { return e.Err }

// validateEntryName returns an InvalidEntryNameError if name is unusable as an
// archive entry name. pkgName is used only to identify the package in the error.
//
// This is the strict check, for names read out of a package archive. It mirrors
// apk-tools' contains_control_character, which rejects the whole class outright
// because nothing legitimate produces one. Use validateRecordedEntryName for
// names that may have come from an existing installed database instead.
func validateEntryName(pkgName, name string) error {
	if name == "" {
		return InvalidEntryNameError{Package: pkgName, Path: name, Err: ErrEmptyName}
	}
	if containsControlCharacter(name) {
		return InvalidEntryNameError{Package: pkgName, Path: name, Err: ErrControlCharacter}
	}
	return nil
}

// recordToken names the installed-database field a rendered record line belongs
// to, for use in an error message: "T:some description" yields "T:".
//
// The token is what an operator needs in order to find the offending field. A
// positional index would not be: the record is rejected before it is written, so
// there is no line in the database to count to, and the fields emitted depend on
// which of them the package populated.
func recordToken(line string) string {
	if i := strings.IndexByte(line, ':'); i >= 0 {
		return line[:i+1]
	}
	// PackageToInstalled always emits "<token>:<value>", so this is unreachable
	// unless that changes. Say so rather than returning something that looks
	// like a token.
	return "unrecognised line"
}

// validateRecordedEntryName returns an InvalidEntryNameError if name cannot be
// written into the installed database as a single F: or R: value.
//
// It is deliberately more permissive than validateEntryName, because it guards a
// different trust boundary. AddInstalledPackage is reached both from
// installPackage -- where the install paths have already applied the strict
// check to every name -- and from pkg/build, which reads an existing base
// image's database with ParseInstalled and feeds it straight back to be
// rewritten. That second source is not attacker-controlled in the same way: the
// bytes are already in the image, so refusing them fails a build over data that
// has been sitting there harmlessly, and dropping the entry instead would hide a
// file that is really present -- the concealment this package is trying to
// prevent. Only the bytes that break the format are refused:
//
//   - "\n" would end the line and forge a following record.
//   - "\r" is silently eaten by bufio.ScanLines when the record is read back, so
//     the value would not survive a round trip intact.
//
// Neither can reach this function from a database read -- ParseInstalled splits
// on "\n", and strips a "\r" that precedes it -- so in practice this rejects
// only values a library caller synthesised itself.
//
// An empty name is accepted here: since #2389 that is the canonical spelling of
// the top-level directory, which AddInstalledPackage renders as a bare "F:".
func validateRecordedEntryName(pkgName, name string) error {
	if types.ContainsNewline(name) {
		return InvalidEntryNameError{Package: pkgName, Path: name, Err: ErrEmbeddedNewline}
	}
	return nil
}
