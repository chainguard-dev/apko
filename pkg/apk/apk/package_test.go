package apk

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestParsePackage(t *testing.T) {
	for _, c := range []struct {
		apk  string
		want *Package
	}{{
		apk: "hello-wolfi-2.12.1-r0.apk",
		want: &Package{
			Name:        "hello-wolfi",
			Version:     "2.12.1-r0",
			Arch:        "x86_64",
			Description: "the GNU hello world program",
			License:     "GPL-3.0-or-later",
			Origin:      "hello-wolfi",
			// This is sha1 of control section.
			Checksum:      []byte{0x8f, 0xd8, 0x6e, 0x0a, 0x6c, 0x6a, 0x58, 0xa0, 0xd1, 0xf9, 0xa6, 0xca, 0xb2, 0x47, 0x18, 0xf1, 0xef, 0xda, 0x64, 0xca},
			Dependencies:  []string{"so:ld-linux-x86-64.so.2", "so:libc.so.6"},
			Provides:      []string{"cmd:hello=2.12.1-r0"},
			Size:          72791,
			InstalledSize: 640091,
			BuildTime:     time.Date(1970, 5, 23, 21, 21, 18, 0, time.UTC),
			BuildDate:     12345678,
			DataHash:      "3a6c21f20a07bebf261162b5ab13cb041d7c1cc3e1edc644aaa99f109f87d887",
		},
	}, {
		apk: "hello-0.1.0-r0.apk",
		want: &Package{
			Name:        "hello",
			Version:     "0.1.0-r0",
			Arch:        "x86_64",
			Description: "just a test package",
			License:     "Apache-2.0",
			// This is sha1 of control section.
			Checksum:      []byte{0x0c, 0xd5, 0x99, 0x79, 0x69, 0x2f, 0x88, 0xde, 0xcc, 0x25, 0xe7, 0x4b, 0xa5, 0x83, 0x3c, 0xc8, 0x1b, 0xe6, 0x9c, 0x63},
			Dependencies:  []string{"busybox"},
			Size:          499,
			InstalledSize: 4117,
			BuildTime:     time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
			BuildDate:     0,
			DataHash:      "1c6e256b3f9e0629730659382a81f82d4ac81b0f04fc9e70a6b1b5c653989911",
		},
	}, {
		apk: "replaces/replaces-0.0.1-r0.apk",
		want: &Package{
			Name:          "replaces",
			Version:       "0.0.1-r0",
			Arch:          "aarch64",
			Description:   "testdata with multiple replaces",
			Origin:        "replaces",
			Checksum:      []byte{0x7c, 0x71, 0x38, 0x02, 0xc8, 0xde, 0x5d, 0x50, 0xfe, 0xda, 0x41, 0xe0, 0xec, 0x01, 0xef, 0x18, 0x33, 0x7e, 0x14, 0xf8},
			Replaces:      []string{"foo", "bar"},
			Size:          1477,
			InstalledSize: 2532,
			BuildTime:     time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
			BuildDate:     0,
			DataHash:      "71b14cc95cf71f4f6c1666cb1699b3bc4f52d17f5575c893324c8f62bb19d9b3",
		},
	}} {
		t.Run(c.apk, func(t *testing.T) {
			f, err := os.Open("testdata/" + c.apk)
			if err != nil {
				t.Fatalf("opening apk: %v", err)
			}
			defer f.Close()

			stat, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			got, err := ParsePackage(ctx, f, uint64(stat.Size()))
			if err != nil {
				t.Fatalf("ParsePackage(): %v", err)
			}
			if d := cmp.Diff(c.want, got); d != "" {
				t.Errorf("ParsePackage() mismatch (-want  got):\n%s", d)
			}
		})
	}
}
