// Copyright 2024 Chainguard, Inc.
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
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/tarfs"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/sync/errgroup"
)

// MultiArch is a build context that can be used to build a multi-architecture image.
// It is used to coordinate the solvers across architectures to ensure they have a consistent solution.
// It does this by disqualifying any packages that are not present in other architectures.
type MultiArch struct {
	Contexts map[types.Architecture]*Context
}

func NewMultiArch(ctx context.Context, archs []types.Architecture, opts ...Option) (*MultiArch, error) {
	m := &MultiArch{
		Contexts: make(map[types.Architecture]*Context),
	}

	for _, arch := range archs {
		fs := tarfs.New()
		bopts := slices.Clone(opts)
		bopts = append(bopts, WithArch(arch))
		c, err := New(ctx, fs, bopts...)
		if err != nil {
			return nil, err
		}
		m.Contexts[arch] = c
	}

	apks := map[string]*apk.APK{}
	for arch, bc := range m.Contexts {
		apks[arch.String()] = bc.apk
	}

	for _, bc := range m.Contexts {
		bc.apk.Others = apks
	}

	return m, nil
}

func (m *MultiArch) BuildLayers(ctx context.Context) (map[types.Architecture]v1.Layer, error) {
	var (
		g  errgroup.Group
		mu sync.Mutex
	)
	layers := map[types.Architecture]v1.Layer{}
	errs := []error{}
	for arch, bc := range m.Contexts {
		arch, bc := arch, bc

		g.Go(func() error {
			_, layer, err := bc.BuildLayer(ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("for arch %q: %w", arch, err))
				return nil
			}

			mu.Lock()
			defer mu.Unlock()
			layers[arch] = layer

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return layers, errors.Join(errs...)
}
