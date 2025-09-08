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

	apkbuildtypes "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
)

func (sc *Context) WriteSupervisionTree(ctx context.Context, services apkbuildtypes.ImageServices) error {
	log := clog.FromContext(ctx)
	log.Debug("generating supervision tree")

	// generate the leaves
	for service, svccmd := range services {
		svcdir := filepath.Join("sv", service)
		if err := sc.fs.MkdirAll(svcdir, 0777); err != nil {
			return fmt.Errorf("could not make supervision directory: %w", err)
		}

		// Construct dependencies by adding 's6-svwait' if needed, then execute the main command
		runContent := "#!/bin/execlineb\n"
		for _, dep := range svccmd.DependsOn {
			runContent += fmt.Sprintf("foreground { s6-svwait -D /sv/%s }\n", dep)
		}
		runContent += svccmd.Command

		if err := sc.fs.WriteFile(filepath.Join(svcdir, "run"), []byte(runContent), 0755); err != nil {
			return fmt.Errorf("could not write runfile: %w", err)
		}

		// Manage finish scripts according to defined restart policy
		restartPolicy := strings.ToLower(strings.TrimSpace(svccmd.Restart))

		var finishContent string
		switch restartPolicy {
		case "no":
			// Always send down signal
			finishContent = fmt.Sprintf(`#!/bin/execlineb
			s6-svc -D /sv/%s`, service)
		case "on-failure":
			// Send down signal in case the run script exited with zero value
			finishContent = fmt.Sprintf(`#!/bin/execlineb -s1
			if { eltest ${1} -eq 0 }
			s6-svc -D /sv/%s
			`, service)
		}

		if finishContent != "" {
			if err := sc.fs.WriteFile(filepath.Join(svcdir, "finish"), []byte(finishContent), 0755); err != nil {
				return fmt.Errorf("could not write finishfile: %w", err)
			}
		}
	}

	return nil
}
