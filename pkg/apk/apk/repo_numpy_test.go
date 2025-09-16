package apk

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNumpyVersionConstraintWithProvides tests the fix for the numpy package resolution issue
// where packages with version constraints weren't properly resolved when the package name
// was provided by another package with a version in the provides clause.
func TestNumpyVersionConstraintWithProvides(t *testing.T) {
	// Simulate the numpy package scenario as described in the issue
	repo := Repository{}
	index := repo.WithIndex(&APKIndex{
		Packages: []*Package{
			// py3.12-numpy package version 2.1.0
			{
				Name:     "py3.12-numpy",
				Version:  "2.1.0",
				Provides: []string{"py3-numpy=2.1.0"},
			},
			// py3.12-numpy package version 1.26.4
			{
				Name:     "py3.12-numpy",
				Version:  "1.26.4",
				Provides: []string{"py3-numpy=1.26.4"},
			},
			// Another package that provides py3-numpy without version
			{
				Name:     "py3.12-numpy-legacy",
				Version:  "1.25.0",
				Provides: []string{"py3-numpy"},
			},
			// pytorch needs numpy < 2.0
			{
				Name:         "pytorch",
				Version:      "2.0.0",
				Dependencies: []string{"py3-numpy<2.0"},
			},
		},
	})

	resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes([]*RepositoryWithIndex{index}))

	t.Run("resolve py3-numpy<2.0 directly", func(t *testing.T) {
		// When looking for py3-numpy<2.0, it should find packages that provide py3-numpy
		// with a version less than 2.0
		pkgs, err := resolver.ResolvePackage("py3-numpy<2.0", map[*RepositoryPackage]string{})
		require.NoError(t, err)

		// Should find py3.12-numpy 1.26.4 (provides py3-numpy=1.26.4)
		// and py3.12-numpy-legacy 1.25.0 (provides py3-numpy without version, uses package version)
		require.Len(t, pkgs, 2, "should find 2 packages that satisfy py3-numpy<2.0")

		// The first one should be 1.26.4 as it's the highest version < 2.0
		require.Equal(t, "1.26.4", pkgs[0].Version)
		require.Equal(t, "py3.12-numpy", pkgs[0].Name)
	})

	t.Run("resolve pytorch dependencies", func(t *testing.T) {
		// pytorch depends on py3-numpy<2.0, which should resolve correctly
		deps, conflicts, err := resolver.GetPackagesWithDependencies(context.Background(), []string{"pytorch"}, nil)
		require.NoError(t, err)
		require.Empty(t, conflicts)

		// Should have pytorch and py3.12-numpy (1.26.4)
		require.Len(t, deps, 2)

		// Find the numpy package in dependencies
		var numpyPkg *RepositoryPackage
		for _, dep := range deps {
			if dep.Name == "py3.12-numpy" {
				numpyPkg = dep
				break
			}
		}

		require.NotNil(t, numpyPkg, "should have py3.12-numpy in dependencies")
		require.Equal(t, "1.26.4", numpyPkg.Version, "should select numpy 1.26.4 (not 2.1.0)")
	})

	t.Run("versioned provides priority", func(t *testing.T) {
		// When both versioned and unversioned provides exist, versioned should be preferred
		// for version constraint resolution
		pkgs, err := resolver.ResolvePackage("py3-numpy>=1.26", map[*RepositoryPackage]string{})
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(pkgs), 1)

		// Should include both 2.1.0 and 1.26.4
		versions := make(map[string]bool)
		for _, pkg := range pkgs {
			versions[pkg.Version] = true
		}
		require.True(t, versions["2.1.0"], "should include 2.1.0")
		require.True(t, versions["1.26.4"], "should include 1.26.4")
		require.False(t, versions["1.25.0"], "should not include 1.25.0 (less than 1.26)")
	})
}