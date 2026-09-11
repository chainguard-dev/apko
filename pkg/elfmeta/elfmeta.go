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

// Package elfmeta lets a package build pre-compute the ELF facts that
// filesystem-level consumers otherwise re-derive by opening and parsing
// every library — most prominently ld.so.cache generation, which needs only
// each library's machine and SONAMEs but costs a full ELF parse per file to
// learn them.
//
// A producer (melange, or any packaging tool) runs [Extract] over a built
// file and stamps [Xattr] with the encoded [Info]. Consumers read the xattr
// instead of the file; a miss or a malformed value falls back to parsing.
// The stamp is ordinary package metadata: it rides the data section's PAX
// records like any other xattr, is covered by the package signature, and
// persists wherever the package's files do — installed systems and built
// images alike. No consumer removes it.
//
// Stamps live on regular files only: Linux permits user.* xattrs on
// neither symlinks nor special files, so a library's facts are stamped on
// the real file and consumers resolve links before reading.
//
// A stamp is exactly as authoritative as the package carrying it: a
// producer that stamps wrong facts mis-describes its own contents, just as
// it could ship a wrong library outright. Consumers trust it accordingly
// and do not re-derive stamped facts.
package elfmeta

import (
	"debug/elf"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Xattr is the extended attribute carrying an encoded [Info]. It rides
// wherever file metadata rides — tar PAX records, filesystem xattrs — and
// stays with the file for its lifetime. The name is vendored: user.* is a
// namespace shared with every tool on the system.
const Xattr = "user.dev.chainguard.elfmeta"

// Info is the pre-computed metadata: whether the file is a dynamic object at
// all, and if so its machine and SONAMEs. A stamped Info with Dyn=false is
// meaningful — it records "checked, not a dynamic object", sparing consumers
// the parse that would rediscover that.
type Info struct {
	Dyn     bool
	Machine elf.Machine
	Sonames []string
}

// Extract computes Info from an ELF file. A parseable non-dynamic object
// (an executable, say) yields Dyn=false and no error; content that does not
// parse as ELF at all is an error, and producers stamping by filename
// convention typically encode that as Dyn=false too.
func Extract(r io.ReaderAt) (Info, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return Info{}, fmt.Errorf("parsing ELF: %w", err)
	}
	if f.Type != elf.ET_DYN {
		return Info{}, nil
	}
	sonames, err := f.DynString(elf.DT_SONAME)
	if err != nil {
		return Info{}, fmt.Errorf("reading DT_SONAME: %w", err)
	}
	return Info{Dyn: true, Machine: f.Machine, Sonames: sonames}, nil
}

// Encode renders Info as the Xattr value: "none" for a non-dynamic object,
// else "dyn <machine>" followed by one SONAME per line.
func (i Info) Encode() []byte {
	if !i.Dyn {
		return []byte("none")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "dyn %d", uint16(i.Machine))
	for _, s := range i.Sonames {
		b.WriteByte('\n')
		b.WriteString(s)
	}
	return []byte(b.String())
}

// Decode parses an Xattr value.
func Decode(b []byte) (Info, error) {
	s := string(b)
	if s == "none" {
		return Info{}, nil
	}
	lines := strings.Split(s, "\n")
	rest, ok := strings.CutPrefix(lines[0], "dyn ")
	if !ok {
		return Info{}, fmt.Errorf("malformed %s value %q", Xattr, s)
	}
	machine, err := strconv.ParseUint(rest, 10, 16)
	if err != nil {
		return Info{}, fmt.Errorf("malformed machine in %s value %q: %w", Xattr, s, err)
	}
	info := Info{Dyn: true, Machine: elf.Machine(machine)}
	for _, l := range lines[1:] {
		if l != "" {
			info.Sonames = append(info.Sonames, l)
		}
	}
	return info, nil
}

// ParseLibFilename splits a shared-library filename into its name and
// version — "libfoo.so.1" into "libfoo" and "1", "libbar.so" into "libbar"
// and "" — and reports an error for names outside the scheme ldconfig
// considers: per ldconfig(8), files named lib*.so* (regular shared objects)
// or ld-*.so* (the dynamic loader itself).
func ParseLibFilename(realname string) (string, string, error) {
	var name string
	var ver string
	if !strings.HasPrefix(realname, "lib") && !strings.HasPrefix(realname, "ld-") {
		return "", "", fmt.Errorf("filename does not start with 'lib' or 'ld-': %s", realname)
	}
	if before, ok := strings.CutSuffix(realname, ".so"); ok {
		name = before
		ver = ""
		return name, ver, nil
	}
	idx := strings.LastIndex(realname, ".so.")
	if idx < 1 {
		return "", "", fmt.Errorf("invalid library name: %s", realname)
	}
	name = realname[:idx]
	ver = realname[idx+len(".so."):]

	return name, ver, nil
}

// EligibleName reports whether a filename is one an ldconfig-style scan
// would consider — the shape producers stamp by.
func EligibleName(realname string) bool {
	_, _, err := ParseLibFilename(realname)
	return err == nil
}
