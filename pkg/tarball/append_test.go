package tarball_test

import (
	"bytes"
	"embed"
	"io"
	"testing"

	"chainguard.dev/apko/pkg/tarball"
	"github.com/stretchr/testify/require"
)

//go:embed testdata
var testdataFS embed.FS

//go:embed testdata/foo
var fooFS embed.FS

//go:embed testdata/bar
var barFS embed.FS

func TestMultiTar(t *testing.T) {
	ctx, err := tarball.NewContext()
	require.NoError(t, err)

	var got bytes.Buffer

	m := tarball.Out(&got)
	require.NoError(t, m.Append(ctx, testdataFS))
	m.Close()

	var expected bytes.Buffer
	require.NoError(t, ctx.WriteArchive(&expected, testdataFS))

	require.Equal(t, expected, got)
}

func TestExtraWriter(t *testing.T) {
	ctx, err := tarball.NewContext()
	require.NoError(t, err)

	var gotFoo bytes.Buffer
	var gotBar bytes.Buffer

	m := tarball.Out(io.Discard)
	require.NoError(t, m.Append(ctx, barFS, &gotBar))
	require.NoError(t, m.Append(ctx, fooFS, &gotFoo))
	m.Close()

	var expectedFoo bytes.Buffer
	var expectedBar bytes.Buffer
	require.NoError(t, ctx.WriteArchive(&expectedBar, barFS))
	require.NoError(t, ctx.WriteArchive(&expectedFoo, fooFS))

	require.Equal(t, expectedFoo, gotFoo)
	require.Equal(t, expectedBar, gotBar)
}
