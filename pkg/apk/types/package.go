// Copyright 2026 Chainguard, Inc.
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

package types

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"gopkg.in/ini.v1"
)

// ErrEmbeddedNewline is returned when a .PKGINFO value spans more than one
// line. apk-tools reads .PKGINFO with a plain line splitter and cannot produce
// or observe such a value; accepting one lets a crafted package smuggle a
// newline into fields that are later written verbatim into line-oriented
// databases. Match it with errors.Is.
var ErrEmbeddedNewline = errors.New("value contains an embedded newline, which apk does not support")

// InvalidFieldError is returned when a .PKGINFO field value cannot be used.
// Use errors.As to recover the field name and value.
type InvalidFieldError struct {
	// Field is the .PKGINFO key, e.g. "pkgdesc".
	Field string

	// Value is the offending value.
	Value string

	// Err is why it was rejected.
	Err error
}

// maxErrorValueLen bounds how much of an offending value an error message
// repeats. The values are attacker-controlled and unbounded, so a hostile
// megabyte description must not become a megabyte log line.
const maxErrorValueLen = 120

// TruncateForError bounds an attacker-controlled value to a length that is
// reasonable to put in an error message or a log line.
//
// Exported so that pkg/apk/apk shares this definition rather than keeping its
// own copy. That package imports this one, so there is no cycle; only the
// reverse direction is impossible.
func TruncateForError(s string) string {
	if len(s) <= maxErrorValueLen {
		return s
	}
	return s[:maxErrorValueLen] + "...(truncated)"
}

func (e InvalidFieldError) Error() string {
	// %q on both: the field name is internally generated but the value is not,
	// and an unescaped newline here would forge log lines from the very input
	// this error exists to reject.
	return fmt.Sprintf(".PKGINFO field %q: %v: %q", e.Field, e.Err, TruncateForError(e.Value))
}

func (e InvalidFieldError) Unwrap() error { return e.Err }

// PackageInfo represents the information present in .PKGINFO.
type PackageInfo struct {
	Name             string   `ini:"pkgname"`
	Version          string   `ini:"pkgver"`
	Arch             string   `ini:"arch"`
	Description      string   `ini:"pkgdesc"`
	License          string   `ini:"license"`
	Origin           string   `ini:"origin"`
	Maintainer       string   `ini:"maintainer"`
	URL              string   `ini:"url"`
	Dependencies     []string `ini:"depend,,allowshadow"`
	Provides         []string `ini:"provides,,allowshadow"`
	InstallIf        []string `ini:"install_if,,allowshadow"`
	Size             uint64   `ini:"size"`
	ProviderPriority uint64   `ini:"provider_priority"`
	BuildDate        int64    `ini:"builddate"`
	RepoCommit       string   `ini:"commit"`
	Replaces         []string `ini:"replaces,,allowshadow"`
	ReplacesPriority uint64   `ini:"replaces_priority"`
	DataHash         string   `ini:"datahash"`
	Triggers         []string `ini:"triggers,,allowshadow"`
}

// AsPackage converts PackageInfo to a Package struct with the given controlHash and size.
func (pkginfo *PackageInfo) AsPackage(controlHash []byte, size uint64) *Package {
	return &Package{
		Name:             pkginfo.Name,
		Version:          pkginfo.Version,
		Arch:             pkginfo.Arch,
		Description:      pkginfo.Description,
		License:          pkginfo.License,
		Origin:           pkginfo.Origin,
		Maintainer:       pkginfo.Maintainer,
		URL:              pkginfo.URL,
		Dependencies:     pkginfo.Dependencies,
		Provides:         pkginfo.Provides,
		InstallIf:        pkginfo.InstallIf,
		InstalledSize:    pkginfo.Size,
		ProviderPriority: pkginfo.ProviderPriority,
		BuildDate:        pkginfo.BuildDate,
		RepoCommit:       pkginfo.RepoCommit,
		Replaces:         pkginfo.Replaces,
		ReplacesPriority: pkginfo.ReplacesPriority,
		DataHash:         pkginfo.DataHash,

		BuildTime: time.Unix(pkginfo.BuildDate, 0).UTC(),
		Checksum:  controlHash,
		Size:      size,
	}
}

// Package represents a single package with the information present in an
// APKINDEX.
type Package struct {
	Name             string `ini:"pkgname"`
	Version          string `ini:"pkgver"`
	Arch             string `ini:"arch"`
	Description      string `ini:"pkgdesc"`
	License          string `ini:"license"`
	Origin           string `ini:"origin"`
	Maintainer       string `ini:"maintainer"`
	URL              string `ini:"url"`
	Checksum         []byte
	Dependencies     []string `ini:"depend,,allowshadow"`
	Provides         []string `ini:"provides,,allowshadow"`
	InstallIf        []string
	Size             uint64 `ini:"size"`
	InstalledSize    uint64
	ProviderPriority uint64 `ini:"provider_priority"`
	BuildTime        time.Time
	BuildDate        int64    `ini:"builddate"`
	RepoCommit       string   `ini:"commit"`
	Replaces         []string `ini:"replaces,,allowshadow"`
	ReplacesPriority uint64   `ini:"replaces_priority"`
	DataHash         string   `ini:"datahash"`
}

func (p *Package) String() string {
	return fmt.Sprintf("%s (ver:%s arch:%s)", p.Name, p.Version, p.Arch)
}
func (p *Package) PackageName() string { return p.Name }

// Filename returns the package filename as it's named in a repository.
func (p *Package) Filename() string {
	// Note: Doesn't use fmt.Sprintf because we call this a lot when we disqualify images.
	return p.Name + "-" + p.Version + ".apk"
}

// ChecksumString returns a human-readable version of the control section checksum.
func (p *Package) ChecksumString() string {
	return "Q1" + base64.StdEncoding.EncodeToString(p.Checksum)
}

// ParsePackageInfo parses the given reader containing the contents of a .PKGINFO
// file and returns a PackageInfo struct.
func ParsePackageInfo(info io.Reader) (*PackageInfo, error) {
	cfg, err := ini.ShadowLoad(info)
	if err != nil {
		return nil, fmt.Errorf("ini.ShadowLoad(): %w", err)
	}

	pkg := &PackageInfo{}
	if err = cfg.MapTo(pkg); err != nil {
		return nil, fmt.Errorf("cfg.MapTo(): %w", err)
	}
	if err := validateNoEmbeddedNewlines(pkg); err != nil {
		return nil, err
	}
	return pkg, nil
}

// validateNoEmbeddedNewlines rejects any string or string-slice field of
// PackageInfo whose value contains a newline or carriage return.
//
// apk-tools reads .PKGINFO as a plain "key = value" line splitter with no
// quoting, so it can neither produce nor observe a multi-line value. go-ini,
// which we use here, honours backquoted and triple-quoted multi-line values by
// default. Accepting those makes apko disagree with apk-tools about the
// contents of the same package, and lets a crafted .PKGINFO smuggle a newline
// into a field that is later written verbatim into line-oriented files -- the
// apk installed database and the triggers database -- where it can forge
// records that propagate into the generated SBOM.
//
// go-ini offers no way to turn its multi-line handling off: every documented
// combination of ini.LoadOptions still yields the joined value. Detecting after
// the fact is therefore the only available route.
//
// The work is done by validateStructNoEmbeddedNewlines, which see for why the
// walk is reflective and how it fails closed.
func validateNoEmbeddedNewlines(pkg *PackageInfo) error {
	return validateStructNoEmbeddedNewlines(reflect.ValueOf(pkg).Elem())
}

// validateStructNoEmbeddedNewlines walks a struct's fields and rejects any that
// carries a line break.
//
// The walk is reflective rather than a fixed list of fields so that a field
// added to PackageInfo later cannot quietly escape validation. Failing closed on
// kinds it cannot prove safe is what makes that true: without it, an unhandled
// field would be skipped in silence. Note also that reflect.Value.String()
// returns a placeholder like "<uint64 Value>" rather than panicking on a
// non-string, so a switch that stopped discriminating correctly would pass
// everything and no test input could tell the difference.
//
// It is split from validateNoEmbeddedNewlines and takes a reflect.Value so that
// the fail-closed paths are reachable from a test: with only PackageInfo's
// current fields every kind is handled, so they are otherwise dead code, and a
// guard nothing can exercise is a guard nobody can trust. A reflect.Value rather
// than an `any` keeps the caller's compile-time safety -- an invalid
// reflect.Value is not something a caller produces by accident, whereas a
// non-pointer or non-struct `any` is.
func validateStructNoEmbeddedNewlines(v reflect.Value) error {
	t := v.Type()

	for i := range v.NumField() {
		// Switch on the value's kind rather than the field's: constructing a
		// reflect.StructField copies the tag and offsets, and this loop runs
		// once per field of every .PKGINFO parsed. It is only needed to name
		// the field in an error, so it is deferred to the rejection paths.
		f := v.Field(i)

		switch f.Kind() {
		case reflect.String:
			if s := f.String(); ContainsNewline(s) {
				return InvalidFieldError{Field: iniKey(t.Field(i)), Value: s, Err: ErrEmbeddedNewline}
			}

		case reflect.Slice:
			if f.Type().Elem().Kind() != reflect.String {
				// Not a []string, so the loop below cannot inspect the elements.
				// Fail closed rather than skipping the field: a []*string or a
				// [][]string carries a newline just as well as a []string, and
				// skipping is exactly the silence the default arm exists to
				// prevent. (A bare `break` here would reach neither.)
				return unprovableFieldError(t.Field(i), f.Type())
			}
			for j := range f.Len() {
				if s := f.Index(j).String(); ContainsNewline(s) {
					return InvalidFieldError{
						Field: fmt.Sprintf("%s entry %d", iniKey(t.Field(i)), j),
						Value: s,
						Err:   ErrEmbeddedNewline,
					}
				}
			}

		case reflect.Bool,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64:
			// Cannot hold a string, so cannot carry a newline.

		default:
			// Fail closed. go-ini populates pointer and nested-struct fields, and
			// those would otherwise be skipped silently. If PackageInfo gains a
			// field of such a kind, extend the cases above deliberately.
			return unprovableFieldError(t.Field(i), f.Type())
		}
	}
	return nil
}

// unprovableFieldError reports a PackageInfo field whose type the validator
// cannot walk. Reaching it means PackageInfo gained a field and the switch above
// was not extended to match, so it names the type rather than just the kind:
// "[]*string" says what to add, where "slice" does not.
func unprovableFieldError(field reflect.StructField, typ reflect.Type) error {
	return fmt.Errorf("internal error: .PKGINFO field %q has unsupported type %s; "+
		"validateStructNoEmbeddedNewlines cannot prove it is free of embedded newlines",
		field.Name, typ)
}

// ContainsNewline reports whether s would occupy more than one line if written
// into a line-oriented format such as .PKGINFO or the installed database.
//
// Exported so that pkg/apk/apk validates against the same definition of "a line
// break" that this package rejects, rather than keeping a second copy. Widening
// it -- to U+2028, say -- then has to be argued once instead of staying
// accidentally consistent across two packages.
//
// IndexByte rather than strings.ContainsAny, which builds an ASCII set per call.
func ContainsNewline(s string) bool {
	return strings.IndexByte(s, '\n') >= 0 || strings.IndexByte(s, '\r') >= 0
}

// iniKey returns the .PKGINFO key a struct field maps to, for error messages.
// Only called on the rejection path: parsing the struct tag on every field of
// every parse costs more than the rest of the validation put together.
func iniKey(field reflect.StructField) string {
	// The ini tag may carry options, e.g. "depend,,allowshadow".
	if key, _, _ := strings.Cut(field.Tag.Get("ini"), ","); key != "" {
		return key
	}
	return field.Name
}
