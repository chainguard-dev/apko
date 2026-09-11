// Copyright 2023 Chainguard, Inc.
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

package apk

const (
	DefaultKeyRingPath       = "/etc/apk/keys"
	DefaultSystemKeyRingPath = "/usr/share/apk/keys/"
	indexFilename            = "APKINDEX.tar.gz"
	// we are using these for fs.FS so should omit the leading /
	reposFilePath     = "etc/apk/repositories"
	archFilePath      = "etc/apk/arch"
	keysDirPath       = "etc/apk/keys"
	worldFilePath     = "etc/apk/world"
	installedFilePath = "usr/lib/apk/db/installed"
	scriptsFilePath   = "usr/lib/apk/db/scripts.tar"
	scriptsTarPerms   = 0o644
	triggersFilePath  = "usr/lib/apk/db/triggers"
	// which PAX record we use in the tar header
	paxRecordsChecksumKey = "APK-TOOLS.checksum.SHA1"

	// for fetching the alpine keys
	alpineReleasesURL = "https://alpinelinux.org/releases.json"

	xattrTarPAXRecordsPrefix = "SCHILY.xattr."
)
