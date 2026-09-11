package build

import (
	"context"
	"testing"

	"chainguard.dev/apko/pkg/apk/fs"
)

func TestLdsoCache(t *testing.T) {
	ctx := context.Background()

	opts := []Option{
		WithConfig("apko.yaml", []string{"testdata"}),
	}

	bc, err := New(ctx, fs.NewMemFS(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	// ld.so.cache is only generated if ld.so.conf exists
	f, err := bc.fs.Create("etc/ld.so.conf")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	err = bc.BuildImage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cache := "etc/ld.so.cache"
	info, err := bc.fs.Stat(cache)
	if err != nil {
		t.Fatal(err)
	}
	mode := info.Mode()
	perm := mode.Perm()
	if perm != 0644 {
		t.Errorf("%s has unexpected permissions: %v", cache, perm)
	}
}
