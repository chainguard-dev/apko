// Copyright 2022, 2023 Chainguard, Inc.
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

package generator

import (
	"context"
	"sync"

	"chainguard.dev/apko/pkg/sbom/options"
)

// Generator defines the interface for SBOM generators.
type Generator interface {
	Key() string
	Ext() string
	Generate(context.Context, *options.Options, string) error
	GenerateIndex(*options.Options, string) error
}

// GeneratorFactory is a function that creates a Generator.
type GeneratorFactory func() Generator

var (
	registryMu sync.RWMutex
	registry   = make(map[string]GeneratorFactory)
)

// RegisterGenerator registers a custom generator factory under the given key.
// This allows external systems to plug in their own SBOM generator types.
// If a generator with the same key already exists, it will be overwritten.
func RegisterGenerator(key string, factory GeneratorFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[key] = factory
}

// Generators returns a map of registered generators.
// If names are provided, only generators with those keys will be returned.
func Generators(names ...string) []Generator {
	generators := []Generator{}

	nameIdx := map[string]bool{}
	for _, n := range names {
		nameIdx[n] = true
	}
	// If no names are provided, return all generators.
	all := len(nameIdx) == 0

	registryMu.RLock()
	defer registryMu.RUnlock()

	for key, factory := range registry {
		if all || nameIdx[key] {
			generators = append(generators, factory())
		}
	}

	return generators
}
