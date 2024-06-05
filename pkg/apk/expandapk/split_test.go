package expandapk

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
)

func TestSplit(t *testing.T) {
	file := "testdata/hello-wolfi-2.12.1-r0.apk"

	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	parts, err := Split(f)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(parts), 3; got != want {
		t.Fatalf("len(Split()): %d != %d", got, want)
	}

	f2, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()

	exp, err := ExpandApk(context.Background(), f2, "")
	if err != nil {
		t.Fatal(err)
	}
	defer exp.Close()

	checks := []string{exp.SignatureFile, exp.ControlFile, exp.PackageFile}

	for i, part := range parts {
		check, err := os.Open(checks[i])
		if err != nil {
			t.Fatal(err)
		}
		defer check.Close()

		want, err := io.ReadAll(check)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(part)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(got, want) {
			t.Errorf("Split() != ExpandAPK() for part %d (%d, %d)", i, len(got), len(want))
		}
	}
}
