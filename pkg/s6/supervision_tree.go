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

package s6

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/clog"
)

func (sc *Context) CreateSupervisionDirectory(ctx context.Context, name string) (string, error) {
	log := clog.FromContext(ctx)

	svbase := "sv"
	svcdir := filepath.Join(svbase, name)
	log.Debugf("  supervision dir: %s", svcdir)

	if err := sc.fs.MkdirAll(svcdir, 0777); err != nil {
		return svcdir, fmt.Errorf("could not make supervision directory: %w", err)
	}
	return svcdir, nil
}

func (sc *Context) WriteSupervisionTemplate(svcdir string, command string) error {
	filename := filepath.Join(svcdir, "run")
	file, err := sc.fs.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		return fmt.Errorf("could not create runfile: %w", err)
	}
	defer file.Close()

	fmt.Fprintf(file, "#!/bin/execlineb\n%s\n", command)

	return nil
}

func (sc *Context) WriteSupervisionServiceSimple(ctx context.Context, name string, command string) error {
	log := clog.FromContext(ctx)
	log.Debugf("simple service: %s => %s", name, command)

	svcdir, err := sc.CreateSupervisionDirectory(ctx, name)
	if err != nil {
		return err
	}

	if err := sc.WriteSupervisionTemplate(svcdir, command); err != nil {
		return err
	}

	return nil
}

func (sc *Context) WriteSupervisionTree(ctx context.Context, services Services) error {
	log := clog.FromContext(ctx)
	log.Debug("generating supervision tree")

	// generate the leaves
	for service, svccmd := range services {
		if err := sc.WriteSupervisionServiceSimple(ctx, service, svccmd); err != nil {
			return err
		}
	}

	return nil
}
