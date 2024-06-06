package tarball

import (
	"archive/tar"
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/fs"
)

func TestWriteTar(t *testing.T) {
	var buf bytes.Buffer
	var (
		m    = fs.NewMemFS()
		dir  = "a"
		file = "a/b"
	)
	err := m.MkdirAll(dir, 0o755)
	require.NoError(t, err, "error creating dir %s", dir)
	err = m.WriteFile(file, []byte("hello world"), 0o644)
	require.NoError(t, err, "error creating file %s", file)

	// set xattrs, then see if the tar gets it
	err = m.SetXattr(dir, "user.dir", []byte("foo"))
	require.NoError(t, err, "error setting xattr on %s", dir)
	err = m.SetXattr(file, "user.file", []byte("bar"))
	require.NoError(t, err, "error setting xattr on %s", file)
	ctx := Context{}
	tw := tar.NewWriter(&buf)
	err = ctx.writeTar(context.TODO(), tw, m, nil, nil)
	require.NoError(t, err, "error writing tar")
	err = tw.Close()
	require.NoError(t, err, "error closing tar writer")

	// now should be able to read the tar and check the xattrs
	tr := tar.NewReader(&buf)
	hdr, err := tr.Next()
	require.NoError(t, err, "error reading dir tar header")
	require.Equal(t, dir, hdr.Name, "tar dir header name mismatch")
	require.Equal(t, "foo", hdr.PAXRecords[xattrTarPAXRecordsPrefix+"user.dir"], "tar header for dir xattr mismatch")

	hdr, err = tr.Next()
	require.NoError(t, err, "error reading file tar header")
	require.Equal(t, file, hdr.Name, "tar file header name mismatch")
	require.Equal(t, "bar", hdr.PAXRecords[xattrTarPAXRecordsPrefix+"user.file"], "tar header for file xattr mismatch")
}
