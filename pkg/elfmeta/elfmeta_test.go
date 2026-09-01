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

package elfmeta

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"reflect"
	"testing"
)

// testELF synthesizes a minimal ELF64 little-endian object of the given type
// with one DT_SONAME entry, just enough for debug/elf's Type, Machine, and
// DynString to work with.
func testELF(t *testing.T, typ elf.Type, machine elf.Machine, soname string) []byte {
	t.Helper()
	dynstr := append([]byte{0}, append([]byte(soname), 0)...)
	const (
		ehsize  = 64
		shentsz = 64
		shnum   = 3
	)
	shoff := int64(ehsize)
	dynstrOff := shoff + shnum*shentsz
	dynOff := dynstrOff + int64(len(dynstr))

	var buf bytes.Buffer
	// ELF header.
	buf.Write([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	le := binary.LittleEndian
	w := func(v any) { _ = binary.Write(&buf, le, v) }
	w(uint16(typ))     // e_type
	w(uint16(machine)) // e_machine
	w(uint32(1))       // e_version
	w(uint64(0))       // e_entry
	w(uint64(0))       // e_phoff
	w(uint64(shoff))   // e_shoff
	w(uint32(0))       // e_flags
	w(uint16(ehsize))  // e_ehsize
	w(uint16(0))       // e_phentsize
	w(uint16(0))       // e_phnum
	w(uint16(shentsz)) // e_shentsize
	w(uint16(shnum))   // e_shnum
	w(uint16(0))       // e_shstrndx

	type shdr struct {
		Name, Type           uint32
		Flags, Addr, Off, Sz uint64
		Link, Info           uint32
		Align, Entsize       uint64
	}
	w(shdr{})                                                                                           // null section
	w(shdr{Type: uint32(elf.SHT_DYNAMIC), Off: uint64(dynOff), Sz: 32, Link: 2, Align: 8, Entsize: 16}) // .dynamic
	w(shdr{Type: uint32(elf.SHT_STRTAB), Off: uint64(dynstrOff), Sz: uint64(len(dynstr)), Align: 1})    // .dynstr
	buf.Write(dynstr)
	w(uint64(elf.DT_SONAME)) // .dynamic: DT_SONAME -> offset 1
	w(uint64(1))
	w(uint64(elf.DT_NULL))
	w(uint64(0))
	return buf.Bytes()
}

func TestExtract(t *testing.T) {
	dyn := testELF(t, elf.ET_DYN, elf.EM_AARCH64, "libfake.so.1")
	info, err := Extract(bytes.NewReader(dyn))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	want := Info{Dyn: true, Machine: elf.EM_AARCH64, Sonames: []string{"libfake.so.1"}}
	if !reflect.DeepEqual(info, want) {
		t.Errorf("Extract: got = %+v, wanted = %+v", info, want)
	}

	exe := testELF(t, elf.ET_EXEC, elf.EM_X86_64, "ignored")
	info, err = Extract(bytes.NewReader(exe))
	if err != nil {
		t.Fatalf("Extract(ET_EXEC): %v", err)
	}
	if info.Dyn {
		t.Errorf("Extract(ET_EXEC): got = dynamic, wanted = not")
	}

	if _, err := Extract(bytes.NewReader([]byte("just some text, not an ELF"))); err == nil {
		t.Error("Extract(non-ELF): got = nil, wanted an error")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	for _, info := range []Info{
		{},
		{Dyn: true, Machine: elf.EM_AARCH64, Sonames: []string{"libc.so.6"}},
		{Dyn: true, Machine: elf.EM_X86_64, Sonames: []string{"liba.so.1", "libb.so.2"}},
		{Dyn: true, Machine: elf.EM_RISCV},
	} {
		got, err := Decode(info.Encode())
		if err != nil {
			t.Fatalf("Decode(Encode(%+v)): %v", info, err)
		}
		if !reflect.DeepEqual(got, info) {
			t.Errorf("round trip: got = %+v, wanted = %+v", got, info)
		}
	}
	for _, bad := range []string{"", "dyn", "dyn x", "wat 42"} {
		if _, err := Decode([]byte(bad)); err == nil {
			t.Errorf("Decode(%q): got = nil, wanted an error", bad)
		}
	}
}

func TestEligibleName(t *testing.T) {
	for name, want := range map[string]bool{
		"libc.so.6":       true,
		"libfoo.so":       true,
		"ld-linux.so.2":   true,
		"libbar.so.1.2.3": true,
		"python3":         false,
		"lib":             false,
		"foo.so":          false,
		"libnodots":       false,
	} {
		if got := EligibleName(name); got != want {
			t.Errorf("EligibleName(%q): got = %v, wanted = %v", name, got, want)
		}
	}
}
