package apk

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSinglePackage(t *testing.T) {
	assert := assert.New(t)

	apkIndexFile := strings.NewReader(`C:Q1Deb0jNytkrjPW4N/eKLZ43BwOlw=
P:a-pkg
V:1.2.3-r1
A:x86_64
S:9180
I:40960
T:A sample package
U:http://a.package.org
L:Apache-2.0
o:a-pkg
m:maintainer <maint@iner.org>
t:1600096848
c:af13bd168c9d86ede4ad1be5c4ceac79253a7e26
D:so:libc.musl-x86_64.so.1
p:thing1 thing2
i:abc xyz
k:9001

`)

	packages, err := ParsePackageIndex(io.NopCloser(apkIndexFile))
	require.NoError(t, err)

	require.Len(t, packages, 1, "Expected exactly 1 package")

	pkg := packages[0]

	assert.Equal("a-pkg", pkg.Name)
	assert.Equal("1.2.3-r1", pkg.Version)
	assert.Equal("x86_64", pkg.Arch)
	assert.Equal("Apache-2.0", pkg.License)
	assert.Equal("A sample package", pkg.Description)
	assert.Equal("a-pkg", pkg.Origin)
	assert.Equal("maintainer <maint@iner.org>", pkg.Maintainer)
	assert.Equal("http://a.package.org", pkg.URL)
	assert.Equal([]string{"so:libc.musl-x86_64.so.1"}, pkg.Dependencies)
	assert.Equal([]string{"thing1", "thing2"}, pkg.Provides)
	assert.Equal([]string{"abc", "xyz"}, pkg.InstallIf)
	assert.EqualValues(9180, pkg.Size)
	assert.EqualValues(40960, pkg.InstalledSize)
	assert.EqualValues(9001, pkg.ProviderPriority)
	require.Equal(t, []byte{
		0xd, 0xe6, 0xf4, 0x8c, 0xdc, 0xad, 0x92, 0xb8, 0xcf, 0x5b,
		0x83, 0x7f, 0x78, 0xa2, 0xd9, 0xe3, 0x70, 0x70, 0x3a, 0x5c,
	}, pkg.Checksum)
	// Ensure the checksums was properly decoded
	require.Equal(t,
		"0de6f48cdcad92b8cf5b837f78a2d9e370703a5c",
		fmt.Sprintf("%x", pkg.Checksum),
	)
}

func TestMultiplePackages(t *testing.T) {
	assert := assert.New(t)

	apkIndexFile := strings.NewReader(`C:Q1Pi7+Lp0TdU9DNxeZKvFbOSjmncw=
P:a-pkg
V:1.2.3-r1
A:x86_64
S:9180
I:40960
T:A sample package
U:http://a.package.org
L:Apache-2.0
o:a-pkg
m:maintainer <maint@iner.org>
t:1600096848
c:af13bd168c9d86ede4ad1be5c4ceac79253a7e26
D:so:libc.musl-x86_64.so.1
p:thing1 thing2
i:abc xyz
k:9001

C:Q1Pi7+Lp0TdU9DNxeZKvFbOSjmncw=
P:b-pkg
V:1.1.1-r1
A:x86_64
S:5243
I:11392
T:Another package
U:http://b.package.org
L:Apache-2.0
o:b-pkg
m:maintainer <maint@iner.org>
t:1600096848
c:af13bd168c9d86ede4ad1be5c4ceac79253a7e26
D:so:libc.musl-x86_64.so.1
p:thing3 thing4
i:def uvw
k:9002

`)

	packages, _ := ParsePackageIndex(io.NopCloser(apkIndexFile))

	require.Len(t, packages, 2, "Expected exactly 2 package")

	assert.Equal("a-pkg", packages[0].Name)
	assert.Equal("b-pkg", packages[1].Name)
}

func TestParseFromArchive(t *testing.T) {
	assert := assert.New(t)

	file, err := os.Open("testdata/APKINDEX.tar.gz")
	require.Nil(t, err)

	apkIndex, err := IndexFromArchive(file)

	require.Nil(t, err)

	assert.NotEmpty(apkIndex.Description, "Description missing")
	assert.Greater(len(apkIndex.Signature), 0, "Signature missing")
	assert.Len(apkIndex.Packages, 2)
}

// Test reading from io.Reader that doesn't implement io.Closer
func TestSinglePackageOnlyReader(t *testing.T) {
	apkIndexFile := strings.NewReader(`C:Q1Deb0jNytkrjPW4N/eKLZ43BwOlw=
P:a-pkg
V:1.2.3-r1
A:x86_64
S:9180
I:40960
T:A sample package
U:http://a.package.org
L:Apache-2.0
o:a-pkg
m:maintainer <maint@iner.org>
t:1600096848
c:af13bd168c9d86ede4ad1be5c4ceac79253a7e26
D:so:libc.musl-x86_64.so.1

`)

	packages, err := ParsePackageIndex(apkIndexFile)
	require.NoError(t, err)

	require.Len(t, packages, 1, "Expected exactly 1 package")
}

func TestArchiveFromIndex(t *testing.T) {
	// Parse original test index archive
	originalArchive, err := os.Open("testdata/APKINDEX.tar.gz")
	require.Nil(t, err)
	originalIndex, err := IndexFromArchive(originalArchive)
	require.Nil(t, err)

	// Attempt to convert index back to an archive
	newArchive, err := ArchiveFromIndex(originalIndex)
	require.Nil(t, err)

	// Ensure that we are able to extract APKINDEX and DESCRIPTION
	// from the new archive and that the contents are correct
	gzipReader, err := gzip.NewReader(newArchive)
	require.Nil(t, err)
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	var foundApkIndex, foundDescription bool
	for {
		hdr, tarErr := tarReader.Next()
		if tarErr == io.EOF {
			break
		}
		require.Nil(t, tarErr)
		switch hdr.Name {
		case apkIndexFilename:
			foundApkIndex = true
			contents, err := io.ReadAll(tarReader)
			require.Nil(t, err)
			b, err := os.ReadFile(fmt.Sprintf("testdata/extracted/%s", apkIndexFilename))
			require.Nil(t, err)
			require.Equal(t, b, contents,
				fmt.Sprintf("Expected %s contents to be:\n%s\nbut were actually:\n%s\n",
					apkIndexFilename, string(b), string(contents)))

		case descriptionFilename:
			foundDescription = true
			contents, err := io.ReadAll(tarReader)
			require.Nil(t, err)
			b, err := os.ReadFile(fmt.Sprintf("testdata/extracted/%s", descriptionFilename))
			require.Nil(t, err)
			require.Equal(t, b, contents,
				fmt.Sprintf("Expected %s contents to be:\n%s\nbut were actually:\n%s\n",
					descriptionFilename, string(b), string(contents)))
		}
	}
	require.Truef(t, foundApkIndex, "Could not locate file %s in archive", apkIndexFilename)
	require.Truef(t, foundDescription, "Could not locate file %s in archive", descriptionFilename)
}

func TestEmptyRepeatedFields(t *testing.T) {
	apkIndexFile := strings.NewReader(`C:Q1Deb0jNytkrjPW4N/eKLZ43BwOlw=
P:a-pkg
V:1.2.3-r1
A:x86_64
S:9180
I:40960
T:A sample package
U:http://a.package.org
L:Apache-2.0
o:a-pkg
m:maintainer <maint@iner.org>
t:1600096848
c:af13bd168c9d86ede4ad1be5c4ceac79253a7e26
D:
p:
i:abc xyz
k:9001

`)

	packages, err := ParsePackageIndex(io.NopCloser(apkIndexFile))
	require.NoError(t, err)

	require.Len(t, packages, 1, "Expected exactly 1 package")

	pkg := packages[0]

	require.Len(t, pkg.Provides, 0, "Expected no provides")
	require.Len(t, pkg.Dependencies, 0, "Expected no dependencies")
}

func TestMultipleKeys(t *testing.T) {
	assert := assert.New(t)
	// read all the keys from testdata/signing/keys
	folder := "testdata/signing/keys"
	// get all the files in the folder
	files, _ := os.ReadDir(folder)
	keys := make(map[string][]byte)
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		// read the file
		keyFile, err := os.Open(fmt.Sprintf("%s/%s", folder, file.Name()))
		require.Nil(t, err)
		// parse the key
		key, err := os.ReadFile(keyFile.Name())
		require.Nil(t, err)
		keys[file.Name()] = key
	}
	// read the index file into []byte
	indexBytes, err := os.ReadFile("testdata/signing/APKINDEX.tar.gz")
	require.Nil(t, err)

	ctx := context.Background()
	// There are 2^N-1 combinations of keys, where N is the number of keys
	// We will test all of them
	for comb := 1; comb < (1 << len(keys)); comb++ {
		// get the keys to use
		usedKeys := make(map[string][]byte)
		for i := 0; i < len(keys); i++ {
			if (comb & (1 << i)) != 0 {
				usedKeys[files[i].Name()] = keys[files[i].Name()]
			}
		}
		// parse the index
		apkIndex, err := parseRepositoryIndex(ctx, "testdata/signing/APKINDEX.tar.gz",
			usedKeys, "aarch64", indexBytes, &indexOpts{})
		require.Nil(t, err)
		assert.Greater(len(apkIndex.Signature), 0, "Signature missing")
	}
	// Now, test the case where we have no matching key
	_, err = parseRepositoryIndex(ctx, "testdata/signing/APKINDEX.tar.gz",
		map[string][]byte{
			"unused-key": []byte("unused-key-data"),
		},
		"aarch64", indexBytes, &indexOpts{})
	require.NotNil(t, err)
}
