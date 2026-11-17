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
//     package, in walk order;
//  2. file contents from packages, by package name and then position in
//     the package's apk.PackageContents.Entries;
//  3. further paths to a package member already in the second group, and
//     then hard links, each in walk order.
//
// Each package's contents are then contiguous and in Entries order. Every
// parent directory precedes its children because directories are in the first
// group, and a hard link's target is in an earlier group or a lower layer.
func partitionTarLayers(ctx context.Context, fsys apkfs.FullFS, groups []*group, pkgToDiff map[*apk.Package][]byte, sinks []layerSink, apkOrder bool) error {
	if !apkOrder {
		return partitionLayers(ctx, fsys, groups, pkgToDiff, sinks)
	}

	layers := make([]orderedLayer, len(sinks))
	buffers := make([]layerSink, len(sinks))
	for i := range layers {
		layers[i].members = map[packageMember]bool{}
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
	first, contents, copies, links []orderedLayerEntry
	// members records the package members in contents.
	members map[packageMember]bool
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
	pkg, name, pos := f.apkSource()
	src := packageMember{pkg, name}
	switch {
	case f.header.Typeflag == tar.TypeLink:
		l.links = append(l.links, entry)
	case pkg != nil && l.members[src]:
		l.copies = append(l.copies, entry)
	case pkg != nil:
		l.members[src] = true
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
	for _, group := range [][]orderedLayerEntry{l.first, l.contents, l.copies, l.links} {
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

// apkSource returns the package and entry name backing f's content, and the
// entry's one-based position in the package's apk.PackageContents.Entries. It
// returns a nil package for content generated or changed during the build,
// and for content whose position is unknown.
func (f *file) apkSource() (pkg *apk.Package, name string, position int) {
	if !hasContent(f.header) {
		return nil, "", 0
	}
	src, ok := f.info.(interface {
		APKSource() (*apk.Package, string, int)
	})
	if !ok {
		return nil, "", 0
	}
	pkg, name, position = src.APKSource()
	if pkg == nil || position <= 0 {
		return nil, "", 0
	}
	return pkg, name, position
}
