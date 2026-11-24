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
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
)

// WriteSupervisionTree writes one s6 service directory per entry in
// services, each with an execlineb run script that executes the command.
//
// The service name becomes a directory name under sv, so it must be a single
// path element: empty names, "." and ".." and names containing a path
// separator are rejected before anything is written.
//
// The command is written as the script's command line verbatim, so that an
// operator can pass arguments, quoting and execline chains as they would in
// a hand-written run script. It is not quoted or otherwise rewritten here.
// Line breaks are allowed: execlineb treats newlines and carriage returns as
// whitespace between words, so a multi-line value (for example a YAML block
// scalar) is still one execline command line, not extra script lines.
func (sc *Context) WriteSupervisionTree(ctx context.Context, services Services) error {
	log := clog.FromContext(ctx)
	log.Debug("generating supervision tree")

	// Check every name first, so that a bad one leaves no partial tree
	// behind: the map's iteration order is random.
	for service := range services {
		if err := validateServiceName(service); err != nil {
			return err
		}
	}

	// generate the leaves
	for service, svccmd := range services {
		svcdir := filepath.Join("sv", service)
		if err := sc.fs.MkdirAll(svcdir, 0777); err != nil {
			return fmt.Errorf("could not make supervision directory: %w", err)
		}

		if err := sc.fs.WriteFile(filepath.Join(svcdir, "run"), fmt.Appendf(nil, "#!/bin/execlineb\n%s\n", svccmd), 0755); err != nil {
			return fmt.Errorf("could not write runfile: %w", err)
		}
	}

	return nil
}

// validateServiceName rejects a service name that is not a single path
// element, so that filepath.Join("sv", service) cannot leave the sv tree.
func validateServiceName(service string) error {
	switch {
	case service == "", service == ".", service == "..":
		return fmt.Errorf("invalid service name %q", service)
	case strings.ContainsAny(service, `/\`+"\x00"):
		return fmt.Errorf("invalid service name %q: must not contain a path separator", service)
	}
	return nil
}
