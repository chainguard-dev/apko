// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package apk

func ArchToAPK(in string) string {
	switch in {
	case "i386", "386":
		return "x86"
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "arm/v6":
		return "armhf"
	case "arm/v7":
		return "armv7"
	default:
		return in
	}
}
