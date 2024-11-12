package client

import (
	"testing"

	"chainguard.dev/apko/pkg/apk/apk"
)

func TestLatestPackage(t *testing.T) {
	arch := "x86_64"
	idx := &apk.APKIndex{
		Packages: []*apk.Package{
			{Name: "foo", Version: "1.0.0", Arch: arch},
			{Name: "foo", Version: "1.0.1", Arch: arch}, // latest
			{Name: "bar", Version: "1.0.0", Arch: arch}, // only
		},
	}

	for _, c := range []struct {
		name string
		want *apk.Package
	}{
		{"foo", &apk.Package{Name: "foo", Version: "1.0.1", Arch: arch}},
		{"bar", &apk.Package{Name: "bar", Version: "1.0.0", Arch: arch}},
		{"baz", nil}, // not found
	} {
		got := (&Client{}).LatestPackage(idx, c.name)
		if got.String() != c.want.String() {
			t.Errorf("LatestPackage(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
