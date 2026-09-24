//go:build ignore

// Generates testdata/owner-width.tar, the fixture behind
// TestOwnerWidthBoundaries.
//
// It has to be a generator rather than table rows built in the test, because
// archive/tar's writer cannot express these values on a 32-bit platform:
// Header.Uid is an int, and tar.Writer derives the uid/gid PAX records from
// that field, ignoring any the caller supplies in PAXRecords. Running it once
// on a 64-bit host and committing the bytes means the test reads what a real
// tar producer emits, on every architecture.
//
// This is a limitation of the Go writer API, not of tar or of 32-bit hosts. PAX
// records are ASCII text and GNU base-256 is a byte encoding; both represent
// uids far beyond uint32, and a 32-bit process writing the header blocks by
// hand produces these archives fine (verified). An attacker is under no
// obligation to use archive/tar, so nothing here narrows the threat -- only the
// consumer's word size matters.
//
//	go run gen_owner_width_fixture.go
package main

import (
	"archive/tar"
	"fmt"
	"log"
	"os"
	"strconv"
)

// The declared uid/gid values, chosen to cover every boundary where a width or
// sign change bites: the uint32 range ends, the int32 range ends, and the
// narrowing that archive/tar performs on a 32-bit int wraps past both.
var declared = []int64{
	0,          // root, legitimate
	1,          // ordinary, legitimate
	65534,      // nobody, legitimate
	2147483647, // MaxInt32   -- legitimate, largest value a 32-bit int holds
	2147483648, // MaxInt32+1 -- legitimate uint32, overflows a 32-bit int
	4294967295, // MaxUint32  -- legitimate, largest value apko may accept
	4294967296, // 2^32       -- MUST be rejected; narrows to 0 on a 32-bit int
	4294968296, // 2^32+1000  -- MUST be rejected; narrows to 1000
	-1,         // MUST be rejected; the classic wrap to MaxUint32
}

func main() {
	f, err := os.Create("testdata/owner-width.tar")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	tw := tar.NewWriter(f)
	content := []byte("#!/bin/sh\n")

	for _, format := range []struct {
		name string
		f    tar.Format
	}{
		{"pax", tar.FormatPAX},
		{"gnu", tar.FormatGNU},
	} {
		for _, id := range declared {
			// The declared value travels in the entry name so the test needs no
			// side-channel: whatever archive/tar reports for Uid on the reading
			// platform, the name still says what the producer wrote. Mode is
			// 04755 throughout -- an owner that narrows to 0 on a setuid binary
			// is the whole point.
			name := fmt.Sprintf("usr/bin/%s-uid-%s", format.name, strconv.FormatInt(id, 10))
			hdr := &tar.Header{
				Name:     name,
				Typeflag: tar.TypeReg,
				Mode:     0o4755,
				Uid:      int(id),
				Gid:      0,
				Size:     int64(len(content)),
				Format:   format.f,
			}
			if int64(hdr.Uid) != id {
				log.Fatalf("%s: uid %d is not representable in an int on this host; "+
					"generate the fixture on a 64-bit machine", name, id)
			}
			if err := tw.WriteHeader(hdr); err != nil {
				log.Fatalf("WriteHeader(%s): %v", name, err)
			}
			if _, err := tw.Write(content); err != nil {
				log.Fatalf("Write(%s): %v", name, err)
			}

			// Same value in the gid field, so neither bound goes unexercised.
			gname := fmt.Sprintf("usr/bin/%s-gid-%s", format.name, strconv.FormatInt(id, 10))
			ghdr := &tar.Header{
				Name:     gname,
				Typeflag: tar.TypeReg,
				Mode:     0o4755,
				Uid:      0,
				Gid:      int(id),
				Size:     int64(len(content)),
				Format:   format.f,
			}
			if err := tw.WriteHeader(ghdr); err != nil {
				log.Fatalf("WriteHeader(%s): %v", gname, err)
			}
			if _, err := tw.Write(content); err != nil {
				log.Fatalf("Write(%s): %v", gname, err)
			}
		}
	}

	if err := tw.Close(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("wrote testdata/owner-width.tar")
}
