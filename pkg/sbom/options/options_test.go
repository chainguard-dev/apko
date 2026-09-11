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

package options

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPurlQualifierString(t *testing.T) {
	for _, tc := range []struct {
		q PurlQualifiers
		e string
	}{
		{
			// Single value pair
			PurlQualifiers{
				"mediaType": "application/vnd.oci.image.index.v1+json",
			},
			"mediaType=application%2Fvnd.oci.image.index.v1%2Bjson",
		},
		{
			// Multiple value pairs
			PurlQualifiers{
				"arch":      "386",
				"mediaType": "application/vnd.oci.image.manifest.v1+json",
				"os":        "linux",
			},
			"arch=386&mediaType=application%2Fvnd.oci.image.manifest.v1%2Bjson&os=linux",
		},
	} {
		require.Equal(t, tc.e, tc.q.String())
	}
}
