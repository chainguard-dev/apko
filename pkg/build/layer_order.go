// Copyright 2026 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package build

import (
	"archive/tar"
	"cmp"
	"context"
	"fmt"
	"slices"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

// partitionTarLayers partitions fsys into layers as partitionLayers does.
// With apkOrder, it writes each layer's entries in this order:
//
//  1. directories, symlinks, and entries whose content does not come from a
//     known position in a package, in walk order;
//  2. file contents from packages, by package name and then position in
//     the package's apk.PackageContents.Entries, with further paths to one
//     package file right after the first;
//  3. hard links, in walk order.
func partitionTarLayers(ctx context.Context, fsys apkfs.FullFS, groups []*group, pkgToDiff map[*apk.Package][]byte, sinks []layerSink, apkOrder bool) error {
	if !apkOrder {
		return partitionLayers(ctx, fsys, groups, pkgToDiff, sinks)
	}

	layers := make([]orderedLayer, len(sinks))
	buffers := make([]layerSink, len(sinks))
	for i := range layers {
		buffers[i] = &layers[i]
	}
	if err := partitionLayers(ctx, fsys, groups, pkgToDiff, buffers); err != nil {
		return err
	}
	for i := range layers {
		if err := layers[i].writeTo(ctx, sinks[i]); err != nil {
			return fmt.Errorf("layer %d: %w", i, err)
		}
		layers[i] = orderedLayer{}
	}
	return nil
}

// orderedLayer collects one layer's entries into the groups that
// partitionTarLayers writes. File contents are read from the build filesystem
// as each entry is written.
type orderedLayer struct {
	first, contents, links []orderedLayerEntry
}

type orderedLayerEntry struct {
	file
	data []byte
	// pkgName and position order package contents.
	pkgName  string
	position int
}

func (l *orderedLayer) add(f *file) error {
	entry := orderedLayerEntry{file: *f}
	if f.header.Typeflag == tar.TypeDir {
		// Partitioning can reuse a directory with a different mtime in
		// another layer.
		header := *f.header
		entry.header = &header
	}
	pkg, pos := f.packagePosition()
	switch {
	case f.header.Typeflag == tar.TypeLink:
		l.links = append(l.links, entry)
	case pkg != nil:
		entry.pkgName, entry.position = pkg.Name, pos
		l.contents = append(l.contents, entry)
	default:
		l.first = append(l.first, entry)
	}
	return nil
}

func (l *orderedLayer) addData(hdr *tar.Header, data []byte) error {
	l.first = append(l.first, orderedLayerEntry{header: hdr, data: data})
	return nil
}

func (l *orderedLayer) writeTo(ctx context.Context, sink layerSink) error {
	slices.SortStableFunc(l.contents, func(a, b orderedLayerEntry) int {
		return cmp.Or(cmp.Compare(a.pkgName, b.pkgName), cmp.Compare(a.position, b.position))
	})
	for _, group := range [][]orderedLayerEntry{l.first, l.contents, l.links} {
		for _, entry := range group {
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.info == nil {
				if err := sink.addData(entry.header, entry.data); err != nil {
					return err
				}
			} else if err := sink.add(&entry.file); err != nil {
				return err
			}
		}
	}
	return nil
}

// packagePosition returns the package backing f's content and the content's
// one-based position in the package's apk.PackageContents.Entries. It returns
// a nil package for content generated or changed during the build, and for
// content whose position is unknown.
func (f *file) packagePosition() (*apk.Package, int) {
	if !hasContent(f.header) {
		return nil, 0
	}
	src, ok := f.info.(apk.PackageEntryInfo)
	if !ok {
		return nil, 0
	}
	pkg, position := src.Package(), src.PackagePosition()
	if pkg == nil || position <= 0 {
		return nil, 0
	}
	return pkg, position
}
