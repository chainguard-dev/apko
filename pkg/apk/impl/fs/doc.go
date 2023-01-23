// Copyright 2022, 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// package fs provides filesystem interface and implementations.
// All implementations support fs.FS, but also supports full read-write, as well as all
// filesystem features, even those not supported by other OSes, e.g. Chown
// on Windows and Plan9, or Mknod on non-Unix-like. It even supports
// those when running without appropriate permissions, e.g. Chown or
// Mknod when non-root.
// It is up to each implementation to determine how to handle requests for additional
// capabilities, such as Chown when running as non-root. These can be special
// files on disk, kept in-memory, or even coloured strips on the computer, as long as the
// writes and reads are consistent.

package fs
