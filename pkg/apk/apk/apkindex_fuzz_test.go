package apk

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// seedCorpus returns representative APKINDEX bodies: a real one from testdata
// plus the shapes that exercise each typed field and each parse error path.
func seedCorpus(t testing.TB) [][]byte {
	t.Helper()

	seeds := [][]byte{
		// Minimal well-formed entry.
		[]byte("P:hello\nV:1.0-r0\nA:x86_64\n\n"),
		// Every typed field that goes through a converter.
		[]byte("P:a\nV:1\nt:1700000000\nS:1024\nI:2048\nk:10\nC:Q13p8u6N+Qp0mQ0zPMVP7cKQ2Qc=\n\n"),
		// Repeated fields, which split on spaces.
		[]byte("P:a\nV:1\nD:so:libc.so.6 so:libz.so.1\np:cmd:a=1\ni:b c\n\n"),
		// Two records separated by a blank line.
		[]byte("P:a\nV:1\n\nP:b\nV:2\n\n"),
		// Record with no trailing blank line.
		[]byte("P:a\nV:1\n"),
		// Unknown token: must be ignored, not an error.
		[]byte("Z:whatever\nP:a\nV:1\n\n"),
		// Error paths: short line, missing colon, unparseable numerics.
		[]byte("P\n"),
		[]byte("PP:x\n"),
		[]byte("P:a\nt:notanumber\n"),
		[]byte("P:a\nS:-1\n"),
		[]byte("P:a\nk:99999999999999999999999\n"),
		// Checksum path: Q1 prefix with invalid base64.
		[]byte("P:a\nC:Q1!!!!\n"),
		// Checksum path: Q1 and nothing else.
		[]byte("P:a\nC:Q1\n"),
		// Empty / whitespace only.
		[]byte(""),
		[]byte("\n\n\n"),
		// Value containing a colon, and an empty value.
		[]byte("P:a\nU:https://example.com/x:y\nT:\n\n"),
		// Multi-byte leading rune: token is sliced by BYTE, not rune.
		[]byte("é:x\nP:a\nV:1\n\n"),
		// CRLF line endings.
		[]byte("P:a\r\nV:1\r\n\r\n"),
		// NUL inside a value.
		append([]byte("P:a\nV:1\nT:x"), 0x00, '\n', '\n'),
	}

	// A real index from the repo's own testdata, if present.
	for _, p := range []string{
		"../../../internal/cli/testdata/base_image/metadata/x86_64/APKINDEX",
		"../../../internal/cli/testdata/base_image/metadata/aarch64/APKINDEX",
	} {
		if b, err := os.ReadFile(p); err == nil {
			seeds = append(seeds, b)
		}
	}

	return seeds
}

// FuzzParsePackageIndex asserts the parser's contract: for ANY byte sequence it
// returns packages or an error, and never panics. APKINDEX content is fetched
// from a package repository, so it is attacker-influenced input on the path
// that decides which packages get installed into an image.
func FuzzParsePackageIndex(f *testing.F) {
	for _, s := range seedCorpus(f) {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		pkgs, err := ParsePackageIndex(bytes.NewReader(data))
		if err != nil {
			if pkgs != nil {
				t.Fatalf("returned %d packages alongside error %v; callers may use both", len(pkgs), err)
			}
			return
		}
		// A successfully parsed record must at least be addressable by name:
		// a nameless package cannot be resolved, and is silently dropped by
		// the record separator logic, so it should never reach the caller.
		for i, p := range pkgs {
			if p == nil {
				t.Fatalf("package %d is nil", i)
			}
			if p.Name == "" {
				t.Fatalf("package %d parsed with an empty name from %q", i, data)
			}
		}
	})
}

// FuzzParsePackageIndexRoundTrip asserts that whatever the parser accepts, the
// writer can represent: parse -> ArchiveFromIndex -> IndexFromArchive must
// yield the same packages. A divergence here is worse than a crash — it means
// an index entry means one thing on the way in and another on the way out.
func FuzzParsePackageIndexRoundTrip(f *testing.F) {
	for _, s := range seedCorpus(f) {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		first, err := ParsePackageIndex(bytes.NewReader(data))
		if err != nil || len(first) == 0 {
			return // only round-trip what the parser actually accepted
		}

		archive, err := ArchiveFromIndex(&APKIndex{Packages: first})
		if err != nil {
			t.Fatalf("parser accepted an index the writer cannot serialize: %v", err)
		}

		second, err := IndexFromArchive(io.NopCloser(archive))
		if err != nil {
			t.Fatalf("writer produced an archive the parser rejects: %v", err)
		}

		if len(second.Packages) != len(first) {
			t.Fatalf("round trip changed package count: %d -> %d", len(first), len(second.Packages))
		}
		for i := range first {
			a, b := first[i], second.Packages[i]
			if a.Name != b.Name || a.Version != b.Version || a.Arch != b.Arch {
				t.Fatalf("round trip changed identity of package %d: %q/%q/%q -> %q/%q/%q",
					i, a.Name, a.Version, a.Arch, b.Name, b.Version, b.Arch)
			}
			if a.Size != b.Size || a.InstalledSize != b.InstalledSize || a.ProviderPriority != b.ProviderPriority {
				t.Fatalf("round trip changed numeric fields of package %d (%q)", i, a.Name)
			}
			if !bytes.Equal(a.Checksum, b.Checksum) {
				t.Fatalf("round trip changed checksum of package %d (%q)", i, a.Name)
			}
		}
	})
}
