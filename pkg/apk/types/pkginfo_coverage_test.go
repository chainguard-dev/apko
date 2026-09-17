package types

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The hand-written table in pkginfo_validation_test.go happens to omit pkgver,
// arch and datahash, and would miss any field added later.
// validateNoEmbeddedNewlines is reflective precisely so that coverage cannot
// drift -- so derive the table from the struct rather than restating it, and
// drive ParsePackageInfo, the branch-gating entry point, once per field.
func TestParsePackageInfoRejectsEmbeddedNewlinesInEveryField(t *testing.T) {
	for field := range reflect.TypeFor[PackageInfo]().Fields() {
		key, _, _ := strings.Cut(field.Tag.Get("ini"), ",")
		if key == "" {
			t.Errorf("field %s has no ini tag, so ParsePackageInfo cannot populate it "+
				"and this test cannot reach it", field.Name)
			continue
		}

		// go-ini keeps the FIRST value of a repeated non-shadow key, so the
		// preamble must not repeat the key under test, or the malicious value is
		// silently dropped and the subtest passes vacuously.
		var preamble string
		if key != "pkgname" {
			preamble += "pkgname = innocent\n"
		}
		if key != "pkgver" {
			preamble += "pkgver = 1.0\n"
		}

		var body string
		switch {
		case field.Type.Kind() == reflect.String:
			body = fmt.Sprintf("%s%s = \"\"\"legit\nP:forged\"\"\"\n", preamble, key)
		case field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.String:
			body = fmt.Sprintf("%s%s = `legit\nP:forged`\n", preamble, key)
		case field.Type.Kind() == reflect.Uint64, field.Type.Kind() == reflect.Int64:
			// Numeric: go-ini's conversion cannot carry a newline through.
			continue
		default:
			t.Errorf("field %s has kind %s, which this test does not know how to "+
				"exercise; extend the validator's switch and this table together",
				field.Name, field.Type.Kind())
			continue
		}

		t.Run(field.Name, func(t *testing.T) {
			pi, err := ParsePackageInfo(strings.NewReader(body))
			if err == nil {
				t.Fatalf("ParsePackageInfo accepted an embedded newline in %s (ini key %q); "+
					"want rejection. parsed = %+v", field.Name, key, pi)
			}
			if !errors.Is(err, ErrEmbeddedNewline) {
				t.Errorf("%s: error = %v, want it to match ErrEmbeddedNewline", field.Name, err)
			}
			var got InvalidFieldError
			if errors.As(err, &got) && !strings.HasPrefix(got.Field, key) {
				t.Errorf("%s: error names field %q, want it to name the ini key %q so an "+
					"operator can find the offending line", field.Name, got.Field, key)
			}
		})
	}
}

// Every slice row in the hand-written table is a single-element slice carrying
// a newline, so "inspect only element 0", "inspect only the last element" and
// "drop the \r half" are all indistinguishable from the real loop.
func TestParsePackageInfoRejectsNewlinesAtAnySliceOffset(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"offender first of three", "pkgname = i\npkgver = 1.0\ndepend = `bad\nP:forged`\ndepend = libc\ndepend = libssl\n"},
		{"offender middle of three", "pkgname = i\npkgver = 1.0\ndepend = libc\ndepend = `bad\nP:forged`\ndepend = libssl\n"},
		{"offender last of three", "pkgname = i\npkgver = 1.0\ndepend = libc\ndepend = libssl\ndepend = `bad\nP:forged`\n"},
		{"lone carriage return in a slice entry", "pkgname = i\npkgver = 1.0\ndepend = libc\rP:forged\n"},
		{"CRLF in a slice entry", "pkgname = i\npkgver = 1.0\nreplaces = `old\r\nP:forged`\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pi, err := ParsePackageInfo(strings.NewReader(tc.body))
			if err == nil {
				t.Fatalf("ParsePackageInfo accepted %s; want rejection. parsed = %+v", tc.name, pi)
			}
			if !errors.Is(err, ErrEmbeddedNewline) {
				t.Errorf("%s: error = %v, want ErrEmbeddedNewline", tc.name, err)
			}
		})
	}
}

// The check is deliberately narrower than the control-character rule applied to
// archive entry names: only \n and \r can terminate a record in the databases
// these values are written to. Rejecting a tab, a DEL, or a Unicode line
// separator would be over-rejection that breaks real packages, so pin the
// accept side too -- the plausible "helpful" future widening is to the Unicode
// separators, and nothing would otherwise notice.
func TestParsePackageInfoNewlineCheckScope(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantReject bool
	}{
		{name: "lone CR mid-value", body: "pkgname = i\npkgver = 1.0\npkgdesc = a\rb\n", wantReject: true},
		{name: "CRLF in a quoted value", body: "pkgname = i\npkgver = 1.0\npkgdesc = \"\"\"a\r\nb\"\"\"\n", wantReject: true},
		{name: "value that is nothing but a newline", body: "pkgname = i\npkgver = 1.0\npkgdesc = \"\"\"\n\"\"\"\n", wantReject: true},

		{name: "U+2028 line separator is not an apk line break", body: "pkgname = i\npkgver = 1.0\npkgdesc = a\u2028b\n"},
		{name: "U+2029 paragraph separator is not an apk line break", body: "pkgname = i\npkgver = 1.0\npkgdesc = a\u2029b\n"},
		{name: "vertical tab is not an apk line break", body: "pkgname = i\npkgver = 1.0\npkgdesc = a\vb\n"},
		{name: "form feed is not an apk line break", body: "pkgname = i\npkgver = 1.0\npkgdesc = a\fb\n"},
		{name: "NEL U+0085 is not an apk line break", body: "pkgname = i\npkgver = 1.0\npkgdesc = a\u0085b\n"},
		{name: "DEL is not an apk line break", body: "pkgname = i\npkgver = 1.0\npkgdesc = a\x7fb\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pi, err := ParsePackageInfo(strings.NewReader(tc.body))
			switch {
			case tc.wantReject && err == nil:
				t.Fatalf("ParsePackageInfo = nil error, want rejection; parsed = %+v", pi)
			case !tc.wantReject && err != nil:
				t.Fatalf("ParsePackageInfo = %v, want acceptance: apk splits records on \\n "+
					"only, so this byte cannot forge a record and rejecting it would break "+
					"real packages", err)
			}
		})
	}
}

// Real-world descriptions contain backticks, quotes and '#', and this is the
// input class most at risk of over-rejection, because go-ini's quoting is
// positional: a value is treated as quoted when it STARTS with the delimiter.
//
// The oracle here is the parsed value, compared byte-for-byte against the input.
// Asserting only that parsing succeeded and produced no newline is not enough --
// go-ini truncates several of these shapes silently, so a weaker oracle reports
// green on exactly the apko/apk-tools divergence this file exists to police.
//
// Rows whose `want` differs from the input record a real difference between
// go-ini's parsing model and apk-tools' read_info_line. They are here so the
// behaviour is written down, and so that changing it fails this test rather
// than passing unnoticed.
func TestParsePackageInfoQuotingCharactersRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		// value is the raw .PKGINFO value under test.
		value string
		// want is what ParsePackageInfo yields. Where it differs from value,
		// diverges says why apk-tools would read it differently.
		want     string
		diverges string
	}{
		{
			name:  "backtick mid-value",
			value: "use the `foo` command",
			want:  "use the `foo` command",
		},
		{
			name:  "leading single quote",
			value: "'D is not GLib' utility libraries",
			want:  "'D is not GLib' utility libraries",
		},
		{
			name:     "leading backtick closed on the same line",
			value:    "`ls` replacement written in Rust",
			want:     "ls",
			diverges: "go-ini reads a leading backtick as a quote delimiter and drops everything after the closing one",
		},
		{
			name:     "hash mid-value",
			value:    "PKCS#11 wrapper library",
			want:     "PKCS",
			diverges: "go-ini treats '#' as an inline comment; apk-tools' read_info_line has no comment syntax",
		},
		{
			name:     "semicolon mid-value",
			value:    "https://git.kernel.org/?p=x.git;a=summary",
			want:     "https://git.kernel.org/?p=x.git",
			diverges: "go-ini treats ';' as an inline comment; apk-tools' read_info_line has no comment syntax",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "pkgname = i\npkgver = 1.0\npkgdesc = " + tc.value + "\n"
			pi, err := ParsePackageInfo(strings.NewReader(body))
			if err != nil {
				t.Fatalf("ParsePackageInfo(%q) = %v, want acceptance: this shape occurs in real "+
					"packages and apk-tools reads it without complaint", tc.value, err)
			}
			if pi.Description != tc.want {
				t.Errorf("ParsePackageInfo(%q) description = %q, want %q\n"+
					"if the parser's handling of this shape changed, update this row "+
					"(and drop its `diverges` note)",
					tc.value, pi.Description, tc.want)
			}
			if tc.diverges != "" && tc.want == tc.value {
				t.Errorf("row claims a divergence (%s) but want == value; one of the two is stale",
					tc.diverges)
			}
			if tc.diverges == "" && tc.want != tc.value {
				t.Errorf("value %q parses to %q but the row does not say why; a silent truncation "+
					"must be recorded as a divergence, not accepted as normal", tc.value, tc.want)
			}
		})
	}
}

// The validator's default arm exists so that a field of a kind it cannot prove
// newline-free fails closed rather than being skipped in silence. With
// PackageInfo's current fields that arm is unreachable, so exercise it directly
// with synthetic structs -- otherwise deleting the arm changes no test result
// and the guarantee is unenforced.
//
// go-ini really does populate these kinds: pointer and nested-struct fields
// both come back carrying an embedded newline from a crafted .PKGINFO, so this
// is not a hypothetical shape.
func TestValidateNoEmbeddedNewlinesFailsClosedOnUnhandledKinds(t *testing.T) {
	type nested struct {
		Note string `ini:"note"`
	}

	// A value that would forge a record if it reached one, so each row below is
	// a field kind that really can carry the payload the validator must not skip.
	evil := "a\nb"

	cases := []struct {
		name       string
		value      any
		wantClosed bool
	}{
		{
			name:       "pointer to string is not provably newline-free",
			value:      &struct{ P *string }{},
			wantClosed: true,
		},
		{
			name:       "nested struct is not provably newline-free",
			value:      &struct{ S nested }{},
			wantClosed: true,
		},
		{
			name:       "map is not provably newline-free",
			value:      &struct{ M map[string]string }{},
			wantClosed: true,
		},
		{
			name:       "array of string is not provably newline-free",
			value:      &struct{ A [2]string }{},
			wantClosed: true,
		},
		{
			name:       "interface is not provably newline-free",
			value:      &struct{ I any }{},
			wantClosed: true,
		},
		// Slices whose element kind is not String. The validator cannot walk
		// these, so it must not skip them either: go-ini populates pointer and
		// nested-struct fields, and a []*string added to PackageInfo later would
		// otherwise carry a newline straight through.
		{
			name:       "slice of string pointers is not provably newline-free",
			value:      &struct{ P []*string }{P: []*string{&evil}},
			wantClosed: true,
		},
		{
			name:       "slice of string slices is not provably newline-free",
			value:      &struct{ S [][]string }{S: [][]string{{"a\nb"}}},
			wantClosed: true,
		},
		{
			name:       "byte slice is not provably newline-free",
			value:      &struct{ B []byte }{B: []byte("a\nb")},
			wantClosed: true,
		},
		{
			name:       "slice of structs is not provably newline-free",
			value:      &struct{ S []nested }{S: []nested{{Note: "a\nb"}}},
			wantClosed: true,
		},
		// Kinds the validator does handle, as a control: if these started
		// failing, the default arm would be over-broad rather than fail-closed.
		{name: "string is handled", value: &struct{ S string }{S: "fine"}},
		{name: "string slice is handled", value: &struct{ S []string }{S: []string{"fine"}}},
		{name: "uint64 cannot hold a string", value: &struct{ N uint64 }{N: 7}},
		{name: "int64 cannot hold a string", value: &struct{ N int64 }{N: 7}},
		{name: "bool cannot hold a string", value: &struct{ B bool }{B: true}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateStructNoEmbeddedNewlines(reflect.ValueOf(tc.value).Elem())
			if tc.wantClosed && err == nil {
				t.Errorf("validateStructNoEmbeddedNewlines(%T) = nil; an unhandled field kind must "+
					"fail closed, or a field added to PackageInfo later escapes validation "+
					"in silence", tc.value)
			}
			if !tc.wantClosed && err != nil {
				t.Errorf("validateStructNoEmbeddedNewlines(%T) = %v, want nil", tc.value, err)
			}
		})
	}
}

// A value whose FIRST byte is a line break. The scope table has such a row for
// \n, which pins the LF half of ContainsNewline; without the \r counterpart,
// narrowing that half to IndexByte(s,'\r') > 0 survives.
func TestParsePackageInfoRejectsLeadingLineBreak(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"leading LF", "pkgname = i\npkgver = 1.0\npkgdesc = \"\"\"\nb\"\"\"\n"},
		{"leading CR", "pkgname = i\npkgver = 1.0\npkgdesc = \"\"\"\rb\"\"\"\n"},
		{"value is a lone CR", "pkgname = i\npkgver = 1.0\npkgdesc = \"\"\"\r\"\"\"\n"},
		{"leading CR, backquoted", "pkgname = i\npkgver = 1.0\npkgdesc = `\rb`\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pi, err := ParsePackageInfo(strings.NewReader(tc.body))
			if err == nil {
				t.Fatalf("accepted a value starting with a line break; parsed = %+v", pi)
			}
			if !errors.Is(err, ErrEmbeddedNewline) {
				t.Errorf("error = %v, want ErrEmbeddedNewline", err)
			}
		})
	}
}

// This is the site where the offending value is GUARANTEED to contain a
// newline, so the rejection must escape it or the rejection itself forges log
// lines. pkg/apk/apk asserts both escaping and a length bound; this package
// inherited neither.
func TestInvalidFieldErrorEscapesAndBoundsAttackerControlledData(t *testing.T) {
	t.Run("message does not carry a raw newline", func(t *testing.T) {
		_, err := ParsePackageInfo(strings.NewReader(
			"pkgname = i\npkgver = 1.0\npkgdesc = \"\"\"a\n\nP:totally-not-malware\nV:9.9.9\"\"\"\n"))
		if err == nil {
			t.Fatal("want rejection")
		}
		if strings.ContainsAny(err.Error(), "\n\r") {
			t.Errorf("rejection carries a raw newline and can forge log lines: %s",
				strconv.Quote(err.Error()))
		}
	})

	t.Run("field name is escaped too", func(t *testing.T) {
		e := InvalidFieldError{Field: "pkgdesc\nP:forged", Value: "x\ny", Err: ErrEmbeddedNewline}
		if strings.ContainsAny(e.Error(), "\n\r") {
			t.Errorf("message carries a raw newline: %s", strconv.Quote(e.Error()))
		}
	})

	t.Run("a hostile oversized value is truncated but still identified", func(t *testing.T) {
		_, err := ParsePackageInfo(strings.NewReader(
			"pkgname = i\npkgver = 1.0\npkgdesc = \"\"\"" + strings.Repeat("A", 100000) + "\nP:x\"\"\"\n"))
		if err == nil {
			t.Fatal("want rejection")
		}
		if len(err.Error()) > 600 {
			t.Errorf("message is %d bytes; an attacker-sized value must be truncated", len(err.Error()))
		}
		if !strings.Contains(err.Error(), "(truncated)") {
			t.Error("truncation is not signalled, so an operator cannot tell the value was cut")
		}
		if !strings.Contains(err.Error(), "pkgdesc") {
			t.Error("message no longer names the offending field")
		}
	})
}

// The error must name the bare .PKGINFO key an operator can grep for, not the
// raw struct tag with its options. HasPrefix cannot tell "depend" from
// "depend,,allowshadow".
func TestInvalidFieldErrorNamesTheBareIniKey(t *testing.T) {
	_, err := ParsePackageInfo(strings.NewReader(
		"pkgname = i\npkgver = 1.0\ndepend = `libc\nP:forged`\n"))
	if err == nil {
		t.Fatal("want rejection")
	}
	var got InvalidFieldError
	if !errors.As(err, &got) {
		t.Fatalf("error = %v (%T), want InvalidFieldError", err, err)
	}
	if strings.ContainsAny(got.Field, ",") {
		t.Errorf("Field = %q; ini struct-tag options leaked in, so it no longer names a key "+
			"an operator can find in .PKGINFO", got.Field)
	}
	if want := "depend entry 0"; got.Field != want {
		t.Errorf("Field = %q, want %q", got.Field, want)
	}
}
