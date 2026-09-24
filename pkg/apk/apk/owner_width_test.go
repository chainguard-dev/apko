package apk

import (
	"archive/tar"
	"errors"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestOwnerWidthBoundaries walks the whole uid/gid boundary matrix from a
// fixture produced by a real archive/tar writer (see
// gen_owner_width_fixture.go), and asserts that checkArchiveOwner's verdict matches
// what the producer *declared* -- not what the reading platform happens to
// report after narrowing.
//
// That distinction is the entire point. tar.Header.Uid is an int, and
// archive/tar narrows into it before apko ever sees the header:
// reader.go mergePAX does `hdr.Uid = int(id64) // Integer overflow possible`
// for PAX records, and readHeader does `int(p.parseNumeric(...))` for GNU
// base-256. On a 32-bit platform a declared uid of 2^32 therefore arrives as 0,
// satisfies `0 <= uid <= MaxUint32`, and reaches Chown as root -- on a 04755
// file, a setuid-root binary the package never declared. linux/386 is a shipped
// goreleaser target, so this is not hypothetical.
//
// Both encodings are covered because a PAX record leaves the true value behind
// in hdr.PAXRecords["uid"], which a fix could consult, while GNU base-256
// carries no such record and cannot be recovered after narrowing.
//
// Run it on both widths; passing on amd64 alone proves nothing here:
//
//	go test ./pkg/apk/apk/ -run TestOwnerWidthBoundaries
//	GOARCH=386 go test ./pkg/apk/apk/ -run TestOwnerWidthBoundaries
func TestOwnerWidthBoundaries(t *testing.T) {
	f, err := os.Open("testdata/owner-width.tar")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	tr := tar.NewReader(f)
	seen := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading fixture: %v", err)
		}

		format, field, declared, ok := parseOwnerWidthName(hdr.Name)
		if !ok {
			t.Fatalf("fixture entry %q does not encode a declared id; regenerate it", hdr.Name)
		}
		seen++

		t.Run(format+"/"+field+"/"+strconv.FormatInt(declared, 10), func(t *testing.T) {
			err := checkArchiveOwner(hdr)
			gotAccept := err == nil

			// Where an int cannot hold every uint32, archive/tar has already
			// destroyed the declared value and no per-value verdict is
			// possible. checkArchiveOwner refuses everything instead, so that is what
			// this asserts -- including for owners that would be perfectly
			// legitimate on a 64-bit build.
			if math.MaxInt < math.MaxUint32 {
				if gotAccept {
					t.Errorf("declared %s=%d was ACCEPTED on a %d-bit int platform, want refused.\n"+
						"  entry:    %s (mode %04o)\n"+
						"  observed: hdr value %d -- indistinguishable from a package that declared it",
						field, declared, strconv.IntSize, hdr.Name, hdr.Mode&0o7777, ownerField(hdr, field))
				} else if !strings.Contains(err.Error(), "requires a 64-bit build") {
					t.Errorf("declared %s=%d was refused, but not by the width guard.\n"+
						"  error: %v\n"+
						"  want it to explain that validation needs a 64-bit build, so the "+
						"operator can tell an unvalidatable platform from a bad package",
						field, declared, err)
				}
				return
			}

			// A uid is representable iff it fits a uint32. Anything else the
			// package declared must be refused.
			wantAccept := declared >= 0 && declared <= math.MaxUint32

			if gotAccept == wantAccept {
				return
			}

			observed := hdr.Uid
			if field == "gid" {
				observed = hdr.Gid
			}
			narrowed := int64(observed) != declared

			switch {
			case gotAccept && !wantAccept:
				t.Errorf("declared %s=%d was ACCEPTED, want rejected.\n"+
					"  entry:      %s (mode %04o)\n"+
					"  observed:   hdr.%s=%d (narrowed=%t, int is %d bits)\n"+
					"  PAX record: %q\n"+
					"  downstream: EROFS Chown stores uint32(%d) = %d\n"+
					"  => a package declaring an unrepresentable owner installs as uid %d",
					field, declared, hdr.Name, hdr.Mode&0o7777,
					strings.ToUpper(field[:1])+field[1:], observed, narrowed, strconv.IntSize,
					hdr.PAXRecords[field], observed, uint32(observed), uint32(observed)) //nolint:gosec // demonstrating the truncation
			case !gotAccept && wantAccept:
				t.Errorf("declared %s=%d was REJECTED, want accepted.\n"+
					"  entry:      %s\n"+
					"  observed:   hdr.%s=%d (narrowed=%t, int is %d bits)\n"+
					"  error:      %v\n"+
					"  => a legitimate uint32 owner is unusable on this platform",
					field, declared, hdr.Name,
					strings.ToUpper(field[:1])+field[1:], observed, narrowed, strconv.IntSize,
					err)
			}
		})
	}

	// 2 formats x 9 values x 2 fields. A silently short fixture would turn this
	// whole test into a no-op, which is exactly the failure mode it exists to
	// prevent elsewhere.
	if want := 36; seen != want {
		t.Errorf("fixture yielded %d entries, want %d; regenerate with `go run gen_owner_width_fixture.go`", seen, want)
	}
}

// parseOwnerWidthName pulls the format, field and declared id back out of a
// fixture entry name of the form "usr/bin/<format>-<field>-<id>".
func parseOwnerWidthName(name string) (format, field string, declared int64, ok bool) {
	base := name[strings.LastIndex(name, "/")+1:]
	parts := strings.SplitN(base, "-", 3)
	if len(parts) != 3 {
		return "", "", 0, false
	}
	id, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", "", 0, false
	}
	return parts[0], parts[1], id, true
}

// ownerField returns the uid or gid the reading platform actually produced.
func ownerField(h *tar.Header, field string) int {
	if field == "gid" {
		return h.Gid
	}
	return h.Uid
}
