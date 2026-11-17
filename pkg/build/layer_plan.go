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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"maps"
	"runtime"
	"slices"
	"strings"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
)

// planVersion identifies the plan's encoding format. Bump it when the
// encoding or the meaning of the plan's contents changes. Rendering changes
// alone do not require a new version.
const planVersion = "apko layer plan/1"

// LayerPlan describes one layer of a multi-layer build as an ordered list
// of tar entries. Each non-empty regular file has a content digest. A plan
// holds no file content and does not read the build filesystem. Render
// reads content from a LayerContent. Digest identifies the plan, not the
// rendered bytes.
type LayerPlan struct {
	packages []*apk.Package
	entries  []PlanEntry
	// sources holds, for each entry whose content comes unchanged from a
	// package, where to read it. It is parallel to entries.
	sources []packageMember
}

// packageMember names a package file by its name in the package's
// apk.PackageContents.Entries. A nil pkg means the entry's content comes from
// the LayerContent.
type packageMember struct {
	pkg  *apk.Package
	name string
}

// PlanEntry contains a tar header for Render and a content digest for a
// non-empty regular file. The digest has the form "<algorithm>:<hex>".
// It comes from the build filesystem or is the SHA-256 of content read
// or generated during planning.
type PlanEntry struct {
	Header tar.Header
	Digest string
}

// Packages returns the packages whose files are in the layer, sorted by name.
// The top layer contains files no package owns and has no packages.
func (p *LayerPlan) Packages() []*apk.Package { return slices.Clone(p.packages) }

// Entries returns copies of the layer's entries in rendering order.
// Changes to the returned entries do not affect the plan.
func (p *LayerPlan) Entries() []PlanEntry {
	out := make([]PlanEntry, len(p.entries))
	for i, e := range p.entries {
		e.Header.PAXRecords = maps.Clone(e.Header.PAXRecords)
		e.Header.Xattrs = maps.Clone(e.Header.Xattrs) //nolint:staticcheck // Clone deprecated Xattrs to prevent changes through returned entries.
		out[i] = e
	}
	return out
}

// Digest returns the SHA-256 of the encoded plan. The encoding contains a
// format version followed by each entry's archive/tar header and content
// digest. It identifies the plan, not the rendered bytes.
//
// Rendered bytes also depend on apko's writer, the Go version and archive/tar,
// and pgzip and its settings. These are fixed within one process. Callers
// that retain rendered layers across processes must also account for these
// dependencies.
func (p *LayerPlan) Digest() (d [sha256.Size]byte, _ error) {
	h := sha256.New()
	field(h, []byte(planVersion))
	var hdrBuf bytes.Buffer
	for i := range p.entries {
		e := &p.entries[i]
		hdrBuf.Reset()
		// WriteHeader writes the header blocks, including PAX records.
		// The file content it expects next is not written.
		if err := tar.NewWriter(&hdrBuf).WriteHeader(&e.Header); err != nil {
			return d, fmt.Errorf("encoding header %s: %w", e.Header.Name, err)
		}
		field(h, hdrBuf.Bytes())
		field(h, []byte(e.Digest))
	}
	h.Sum(d[:0])
	return d, nil
}

// field writes b to h with a length prefix so distinct field sequences
// have distinct encodings.
func field(h hash.Hash, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	h.Write(n[:])
	h.Write(b)
}

// LayerContent provides content for a build's layer plans by digest. It
// reads files from the build filesystem and holds content generated during
// planning. It trusts digests reported by the filesystem to identify the
// content correctly. The filesystem must remain available and unchanged
// from planning until rendering completes.
type LayerContent struct {
	fsys   apkfs.FullFS
	paths  map[string]string
	inline map[string][]byte
}

func (c *LayerContent) open(digest string) (io.ReadCloser, error) {
	if b, ok := c.inline[digest]; ok {
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	path, ok := c.paths[digest]
	if !ok {
		return nil, fmt.Errorf("no content for %s: %w", digest, fs.ErrNotExist)
	}
	f, err := c.fsys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	return f, nil
}

// PackageReader reads files from one package.
type PackageReader interface {
	// Open returns the content of the package file with the given name, as
	// the package's apk.PackageContents.Entries spell it. For a name in more
	// than one entry, it returns the content of the last.
	Open(member string) (io.ReadCloser, error)
	Close() error
}

// RenderOption configures Render.
type RenderOption func(*renderOptions)

type renderOptions struct {
	newPackageReader func(*apk.Package) (PackageReader, error)
	newHash          func(algorithm string) (hash.Hash, bool)
}

// WithPackageReaders makes Render read file content that comes unchanged from
// a package through a reader returned by newReader. Render keeps one reader
// open at a time: it calls newReader when it needs content from a package
// other than the current reader's, after closing the current reader, and
// closes the last reader before returning. Render reads each member through a
// reader at most once. If the plan was built with WithAPKLayerOrder, Render
// uses one reader per package, in package name order, and Open calls follow
// the order of the package's apk.PackageContents.Entries. Content generated
// or changed during the build, and further entries with the same member's
// content, such as a file reached through two paths, come from the
// LayerContent.
//
// Render checks the content each reader returns against the entry's digest.
// It hashes sha256 digests itself and other algorithms, named by the part of
// the digest before the colon, with a hash from newHash, which may be nil.
// Render returns an error if a digest does not match or it has no hash for
// the digest's algorithm.
func WithPackageReaders(newReader func(*apk.Package) (PackageReader, error), newHash func(algorithm string) (hash.Hash, bool)) RenderOption {
	return func(o *renderOptions) {
		o.newPackageReader = newReader
		o.newHash = newHash
	}
}

// contentHash returns a hash for checking content against digest.
func (o renderOptions) contentHash(digest string) (hash.Hash, error) {
	algorithm, _, ok := strings.Cut(digest, ":")
	if !ok {
		return nil, fmt.Errorf("malformed digest %q", digest)
	}
	if algorithm == "sha256" {
		return sha256.New(), nil
	}
	if o.newHash != nil {
		if h, ok := o.newHash(algorithm); ok {
			return h, nil
		}
	}
	return nil, fmt.Errorf("cannot check %s digests", algorithm)
}

// Render writes p's layer to w as a gzipped tar archive, reading content
// from c, and returns its digests. If it returns an error, what it wrote
// to w is not a valid layer and should be discarded.
func (p *LayerPlan) Render(ctx context.Context, c *LayerContent, w io.Writer, opts ...RenderOption) (*LayerDigests, error) {
	var o renderOptions
	for _, opt := range opts {
		opt(&o)
	}
	// With the same compression settings, pgzip produces the same output
	// regardless of worker count, matching BuildLayers.
	ls, err := newLayerStream(w, true, pgzipThreads)
	if err != nil {
		return nil, err
	}
	if err := p.writeEntries(ctx, ls.tw, c, o); err != nil {
		_, _ = ls.finish()
		return nil, err
	}
	d, err := ls.finish()
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (p *LayerPlan) writeEntries(ctx context.Context, tw *tar.Writer, c *LayerContent, o renderOptions) (err error) {
	var (
		pkg    *apk.Package
		reader PackageReader
	)
	closeReader := func() error {
		if reader == nil {
			return nil
		}
		r := reader
		reader = nil
		if err := r.Close(); err != nil {
			return fmt.Errorf("closing package %s: %w", pkg.Name, err)
		}
		return nil
	}
	defer func() {
		if cerr := closeReader(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	// open returns entry i's content and, for content from a package reader,
	// a hash to check it with.
	open := func(i int) (io.ReadCloser, hash.Hash, error) {
		src := p.sources[i]
		if o.newPackageReader == nil || src.pkg == nil {
			data, err := c.open(p.entries[i].Digest)
			return data, nil, err
		}
		h, err := o.contentHash(p.entries[i].Digest)
		if err != nil {
			return nil, nil, err
		}
		if reader == nil || pkg != src.pkg {
			if err := closeReader(); err != nil {
				return nil, nil, err
			}
			pkg = src.pkg
			reader, err = o.newPackageReader(pkg)
			if err != nil {
				return nil, nil, fmt.Errorf("opening package %s: %w", pkg.Name, err)
			}
		}
		data, err := reader.Open(src.name)
		if err != nil {
			return nil, nil, fmt.Errorf("reading %s from package %s: %w", src.name, src.pkg.Name, err)
		}
		return data, h, nil
	}

	buf := make([]byte, 1<<20)
	for i := range p.entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		e := &p.entries[i]
		hdr := e.Header
		if err := tw.WriteHeader(&hdr); err != nil {
			return fmt.Errorf("writing header %s: %w", hdr.Name, err)
		}
		if !hasContent(&hdr) {
			continue
		}
		data, h, err := open(i)
		if err != nil {
			return fmt.Errorf("%s: %w", hdr.Name, err)
		}
		var dst io.Writer = tw
		if h != nil {
			dst = io.MultiWriter(tw, h)
		}
		_, err = io.CopyBuffer(dst, data, buf)
		// Should never fail in practice.
		cerr := data.Close()
		if err != nil {
			return fmt.Errorf("copying %s: %w", hdr.Name, err)
		}
		if cerr != nil {
			return fmt.Errorf("closing %s: %w", hdr.Name, cerr)
		}
		if h != nil {
			algorithm, want, _ := strings.Cut(e.Digest, ":")
			if got := hex.EncodeToString(h.Sum(nil)); got != want {
				return fmt.Errorf("%s: content has %s digest %s, want %s", hdr.Name, algorithm, got, want)
			}
		}
	}
	return nil
}

// PlanLayers builds the image in the Context's filesystem without writing
// the layers. It returns the plans and the LayerContent needed to render them.
// There is one plan per package group, followed by one for the top layer.
// Rendering the plans produces the same layers as BuildLayers.
//
// The returned LayerContent reads the Context's filesystem. PlanLayers must
// be called at most once per Context and not together with BuildLayers.
// PlanLayers supports only layered tar builds.
func (bc *Context) PlanLayers(ctx context.Context) ([]*LayerPlan, *LayerContent, error) {
	if bc.ic.Layering == nil || (bc.ic.Layering.Strategy == "" && bc.ic.Layering.Budget == 0) {
		return nil, nil, errors.New("planning layers needs a layered configuration")
	}
	if bc.ic.Format.Resolved() != types.LayerFormatTar {
		return nil, nil, fmt.Errorf("planning layers needs the %q layer format, not %q", types.LayerFormatTar, bc.ic.Format.Resolved())
	}
	groups, pkgToDiff, err := bc.layerGroups(ctx)
	if err != nil {
		return nil, nil, err
	}
	return planLayers(ctx, bc.fs, groups, pkgToDiff, bc.o.APKLayerOrder)
}

// planner collects one layer's entries.
type planner struct {
	plan    *LayerPlan
	content *LayerContent
	// read records package members already assigned to an entry.
	read map[packageMember]bool
	// files records entry indices and filesystem sources for digestFiles.
	files []plannedFile
}

// plannedFile is an entry with content from the build filesystem.
type plannedFile struct {
	index int
	path  string
	info  fs.FileInfo
}

func (pl *planner) add(f *file) error {
	var src packageMember
	if hasContent(f.header) {
		pl.files = append(pl.files, plannedFile{index: len(pl.plan.entries), path: f.path, info: f.info})
		src.pkg, src.name, _ = f.apkSource()
		if src.pkg != nil {
			if pl.read[src] {
				// Another entry already reads this member, so this one
				// reads its content from the LayerContent.
				src = packageMember{}
			} else {
				pl.read[src] = true
			}
		}
	}
	pl.plan.entries = append(pl.plan.entries, PlanEntry{Header: *f.header})
	pl.plan.sources = append(pl.plan.sources, src)
	return nil
}

func (pl *planner) addData(hdr *tar.Header, data []byte) error {
	if !hasContent(hdr) {
		pl.plan.entries = append(pl.plan.entries, PlanEntry{Header: *hdr})
		pl.plan.sources = append(pl.plan.sources, packageMember{})
		return nil
	}
	h, _, err := v1.SHA256(bytes.NewReader(data))
	if err != nil {
		return err
	}
	d := h.String()
	pl.plan.entries = append(pl.plan.entries, PlanEntry{Header: *hdr, Digest: d})
	pl.plan.sources = append(pl.plan.sources, packageMember{})
	pl.content.inline[d] = data
	return nil
}

// planLayers walks fsys to plan one layer per group followed by the top layer.
func planLayers(ctx context.Context, fsys apkfs.FullFS, groups []*group, pkgToDiff map[*apk.Package][]byte, apkOrder bool) ([]*LayerPlan, *LayerContent, error) {
	content := &LayerContent{fsys: fsys, paths: map[string]string{}, inline: map[string][]byte{}}
	planners := make([]*planner, 0, len(groups)+1)
	sinks := make([]layerSink, 0, len(groups)+1)
	newPlanner := func(pkgs []*apk.Package) {
		pl := &planner{plan: &LayerPlan{packages: pkgs}, content: content, read: map[packageMember]bool{}}
		planners = append(planners, pl)
		sinks = append(sinks, pl)
	}
	for _, g := range groups {
		newPlanner(slices.Clone(g.pkgs))
	}
	newPlanner(nil)
	if err := partitionTarLayers(ctx, fsys, groups, pkgToDiff, sinks, apkOrder); err != nil {
		return nil, nil, err
	}
	if err := digestFiles(ctx, fsys, planners, content); err != nil {
		return nil, nil, err
	}
	plans := make([]*LayerPlan, len(planners))
	for i, pl := range planners {
		plans[i] = pl.plan
	}
	return plans, content, nil
}

// digestFiles assigns content digests to planned files, processing each path
// once in parallel. It records the first planned path for each digest in
// content.
func digestFiles(ctx context.Context, fsys apkfs.FullFS, planners []*planner, content *LayerContent) error {
	var (
		mu      sync.Mutex
		digests = map[string]string{}
	)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.GOMAXPROCS(0))
	queued := map[string]bool{}
	for _, pl := range planners {
		for _, f := range pl.files {
			if queued[f.path] {
				continue
			}
			queued[f.path] = true
			g.Go(func() error {
				d, err := fileDigest(gctx, fsys, f)
				if err != nil {
					return err
				}
				mu.Lock()
				digests[f.path] = d
				mu.Unlock()
				return nil
			})
		}
	}
	if err := g.Wait(); err != nil {
		return err
	}
	for _, pl := range planners {
		for _, f := range pl.files {
			d := digests[f.path]
			pl.plan.entries[f.index].Digest = d
			if _, ok := content.paths[d]; !ok {
				content.paths[d] = f.path
			}
		}
		pl.files = nil
	}
	return nil
}

// fileDigest returns f's FileInfo.ContentDigest result if non-empty.
// Otherwise, it reads the file through fsys and returns its SHA-256 digest.
func fileDigest(ctx context.Context, fsys apkfs.FullFS, f plannedFile) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if cd, ok := f.info.(interface{ ContentDigest() (string, error) }); ok {
		d, err := cd.ContentDigest()
		if err != nil {
			return "", fmt.Errorf("naming %s: %w", f.path, err)
		}
		if d != "" {
			return d, nil
		}
	}
	r, err := fsys.Open(f.path)
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", f.path, err)
	}
	defer r.Close()
	h, _, err := v1.SHA256(r)
	if err != nil {
		return "", fmt.Errorf("hashing %s: %w", f.path, err)
	}
	return h.String(), nil
}
