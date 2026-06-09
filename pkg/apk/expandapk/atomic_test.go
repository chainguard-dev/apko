package expandapk

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// midWriteChecker is an io.Reader that, after the first chunk it returns has
// been written by the copier, asserts that the destination path does not yet
// exist. If the write were done in place (os.Create on the destination), the
// destination would already hold a partial file at this point.
type midWriteChecker struct {
	t       *testing.T
	dst     string
	data    []byte
	off     int
	checked bool
}

func (r *midWriteChecker) Read(p []byte) (int, error) {
	if r.off > 0 && !r.checked {
		r.checked = true
		if _, err := os.Stat(r.dst); !errors.Is(err, fs.ErrNotExist) {
			r.t.Errorf("destination %q is observable mid-write (stat err=%v); write is not atomic", r.dst, err)
		}
	}
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	// Cap each Read at 64 KiB to force several Read calls, so a chunk is
	// flushed before the next destination check.
	n := min(copy(p, r.data[r.off:]), 64*1024)
	r.off += n
	return n, nil
}

func TestWriteFileAtomic_DestinationNotVisibleUntilComplete(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "data.tar")

	payload := bytes.Repeat([]byte("x"), 256*1024)
	r := &midWriteChecker{t: t, dst: dst, data: payload}

	if err := writeFileAtomic(dst, r); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	if !r.checked {
		t.Fatal("mid-write check never ran; the test would not catch a regression")
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("reading destination: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("destination content mismatch: got %d bytes, want %d", len(got), len(payload))
	}

	// The temp file must have been renamed, not left behind.
	if ents, err := os.ReadDir(dir); err != nil {
		t.Fatal(err)
	} else if len(ents) != 1 {
		t.Fatalf("expected only the destination file, found %v (temp not cleaned up?)", entryNames(ents))
	}
}

// errAfter yields its data once and then returns a fixed error.
type errAfter struct {
	data []byte
	err  error
	done bool
}

func (r *errAfter) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		return copy(p, r.data), nil
	}
	return 0, r.err
}

func TestWriteFileAtomic_FailedWriteLeavesNoDestination(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "data.tar")

	payload := bytes.Repeat([]byte("y"), 256*1024)
	outOfReadsError := errors.New("single-use reader has no reads left")
	r := &errAfter{data: payload, err: outOfReadsError}

	if err := writeFileAtomic(dst, r); !errors.Is(err, outOfReadsError) {
		t.Fatalf("expected error wrapping %v, got %v", outOfReadsError, err)
	}
	if _, err := os.Stat(dst); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("destination must not exist after a failed write (stat err=%v)", err)
	}
	if ents, err := os.ReadDir(dir); err != nil {
		t.Fatal(err)
	} else if len(ents) != 0 {
		t.Fatalf("temp file not cleaned up after failed write: %v", entryNames(ents))
	}
}

func entryNames(ents []os.DirEntry) []string {
	names := make([]string, len(ents))
	for i, e := range ents {
		names[i] = e.Name()
	}
	return names
}
