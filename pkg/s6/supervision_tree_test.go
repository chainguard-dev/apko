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

package s6

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

func TestWriteSupervisionTree(t *testing.T) {
	fsys := apkfs.NewMemFS()
	sc := New(fsys)

	err := sc.WriteSupervisionTree(context.Background(), Services{
		"web": `/usr/bin/nginx -g "daemon off;"`,
	})
	require.NoError(t, err)

	got, err := fsys.ReadFile("sv/web/run")
	require.NoError(t, err)
	require.Equal(t, "#!/bin/execlineb\n/usr/bin/nginx -g \"daemon off;\"\n", string(got),
		"the command is written verbatim as the script's one command line")
}

// TestWriteSupervisionTreeKeepsMultilineCommand checks that a command with
// line breaks, as a YAML block scalar produces, is written verbatim:
// execlineb reads newlines as whitespace, so this is still one command line.
func TestWriteSupervisionTreeKeepsMultilineCommand(t *testing.T) {
	fsys := apkfs.NewMemFS()
	cmd := "foreground { /usr/bin/setup }\n/usr/bin/nginx -g \"daemon off;\"\n"

	require.NoError(t, New(fsys).WriteSupervisionTree(context.Background(), Services{"web": cmd}))

	got, err := fsys.ReadFile("sv/web/run")
	require.NoError(t, err)
	require.Equal(t, "#!/bin/execlineb\n"+cmd+"\n", string(got))
}

func TestWriteSupervisionTreeRejectsBadServiceName(t *testing.T) {
	for name, service := range map[string]string{
		"empty":        "",
		"dot":          ".",
		"dotdot":       "..",
		"traversal":    "../../../tmp/evil",
		"nested":       "a/b",
		"backslash":    `a\b`,
		"absolute":     "/etc",
		"embedded nul": "a\x00b",
	} {
		t.Run(name, func(t *testing.T) {
			// Several valid services alongside the bad one: map iteration
			// order is random, so this checks that the names are validated
			// before any service directory is written.
			services := Services{service: "/usr/bin/true"}
			for _, ok := range []string{"a", "b", "c", "d", "e", "f"} {
				services[ok] = "/usr/bin/true"
			}
			fsys := apkfs.NewMemFS()
			err := New(fsys).WriteSupervisionTree(context.Background(), services)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid service name")

			entries, err := fsys.ReadDir(".")
			require.NoError(t, err)
			require.Empty(t, entries, "nothing may be written when a service name is rejected")
		})
	}
}
