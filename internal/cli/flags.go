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

package cli

import (
	"github.com/spf13/cobra"

	"chainguard.dev/apko/pkg/options"
)

// addClientLimitFlags adds size limit flags for APK client operations (fetching indexes, expanding packages).
func addClientLimitFlags(cmd *cobra.Command, limits *options.SizeLimits) {
	defaults := options.DefaultSizeLimits()

	cmd.Flags().Int64Var(&limits.APKIndexDecompressedMaxSize, "max-apkindex-decompressed-size", defaults.APKIndexDecompressedMaxSize,
		"maximum decompressed size for APKINDEX archives in bytes, protects against gzip bombs (0=default, -1=no limit)")
	cmd.Flags().Int64Var(&limits.APKControlMaxSize, "max-apk-control-size", defaults.APKControlMaxSize,
		"maximum decompressed size for APK control sections in bytes (0=default, -1=no limit)")
	cmd.Flags().Int64Var(&limits.APKDataMaxSize, "max-apk-data-size", defaults.APKDataMaxSize,
		"maximum decompressed size for APK data sections in bytes, protects against gzip bombs (0=default, -1=no limit)")
	cmd.Flags().Int64Var(&limits.HTTPResponseMaxSize, "max-http-response-size", defaults.HTTPResponseMaxSize,
		"maximum size for HTTP responses in bytes (0=default, -1=no limit)")
}
