package expandapk

import (
	"archive/tar"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

func checksumFromHeader(header *tar.Header) ([]byte, error) {
	pax := header.PAXRecords
	if pax == nil {
		return nil, nil
	}

	hexsum, ok := pax[paxRecordsChecksumKey]
	if !ok {
		return nil, nil
	}

	if b64, ok := strings.CutPrefix(hexsum, "Q1"); ok {
		// This is nonstandard but something we did at one point, handle it.
		// In other contexts, this Q1 prefix means "this is sha1 not md5".
		checksum, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("decoding base64 checksum from header for %q: %w", header.Name, err)
		}

		return checksum, nil
	}

	checksum, err := hex.DecodeString(hexsum)
	if err != nil {
		return nil, fmt.Errorf("decoding hex checksum from header for %q: %w", header.Name, err)
	}

	return checksum, nil
}
