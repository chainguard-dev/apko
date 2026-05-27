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

package erofsmount

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	erofs "github.com/erofs/go-erofs"
)

// OpenLayers opens every EROFS layer referenced by src and returns them in
// bottom-up order (layers[0] is the base). The returned close function must
// be called when the caller is done with the layers; it closes the
// underlying os.File handles.
//
// For KindBlob, the returned slice has exactly one element. For KindOCIDir
// arch may be "" or "host" (process arch) or a specific GOARCH value.
func OpenLayers(src Source, arch string) (layers []fs.FS, close func() error, err error) {
	var files []*os.File
	cleanup := func() error {
		var errs []error
		for _, f := range files {
			if cerr := f.Close(); cerr != nil {
				errs = append(errs, cerr)
			}
		}
		return errors.Join(errs...)
	}
	// On any error before we return, close everything we already opened.
	defer func() {
		if err != nil {
			_ = cleanup()
		}
	}()

	switch src.Kind {
	case KindBlob:
		f, l, oerr := openOneBlob(src.Path)
		if oerr != nil {
			return nil, nil, oerr
		}
		files = append(files, f)
		layers = []fs.FS{l}

	case KindOCIDir:
		refs, oerr := ReadOCILayers(src.Path, src.Tag, arch)
		if oerr != nil {
			return nil, nil, oerr
		}
		layers = make([]fs.FS, 0, len(refs))
		for _, ref := range refs {
			f, l, oerr := openOneBlob(ref.BlobPath)
			if oerr != nil {
				return nil, nil, fmt.Errorf("open layer %s: %w", ref.Digest, oerr)
			}
			files = append(files, f)
			layers = append(layers, l)
		}

	default:
		return nil, nil, fmt.Errorf("unsupported source kind: %v", src.Kind)
	}

	return layers, cleanup, nil
}

func openOneBlob(path string) (*os.File, fs.FS, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	l, err := erofs.Open(f)
	if err != nil {
		_ = f.Close()
		return nil, nil, wrapErofsErr(path, err)
	}
	return f, l, nil
}

// wrapErofsErr turns go-erofs's ErrNotImplemented into an actionable message
// pointing the user at the mount-based path. Other errors pass through.
func wrapErofsErr(path string, err error) error {
	if errors.Is(err, erofs.ErrNotImplemented) {
		return fmt.Errorf("read %s: this EROFS image uses a feature go-erofs does not yet support (typically compression); use `apko erofs mount` to inspect via the kernel or erofsfuse instead: %w", path, err)
	}
	return fmt.Errorf("erofs.Open %s: %w", path, err)
}
