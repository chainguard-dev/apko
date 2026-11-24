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

package types_test

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/build/types"
)

// TestIncludedUID0UserIsRejected loads a configuration whose own accounts
// are fine but whose include declares a UID 0 user. Every file is checked
// as it is loaded, the include too, and the merged result is checked again,
// so the include cannot smuggle the user past Load. The error here comes
// from the include's own load, so it names the include file.
func TestIncludedUID0UserIsRejected(t *testing.T) {
	ic := types.ImageConfiguration{}
	err := ic.Load(context.Background(), filepath.Join("testdata", "include-uid0", "main.apko.yaml"), []string{"testdata"}, sha256.New())
	require.Error(t, err)
	require.Contains(t, err.Error(), "UID 0")
	require.Contains(t, err.Error(), "include", "the included file is refused as it is loaded")
}

func TestValidateRejectsUID0User(t *testing.T) {
	ic := types.ImageConfiguration{
		Accounts: types.ImageAccounts{
			Users: []types.User{{UserName: "toor", UID: 0}},
		},
	}
	err := ic.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "UID 0")

	ic.Accounts.Users = []types.User{{UserName: "app", UID: 65532}}
	require.NoError(t, ic.Validate())
	require.Equal(t, "/home/app", ic.Accounts.Users[0].HomeDir, "Validate still fills in the home directory")
}
