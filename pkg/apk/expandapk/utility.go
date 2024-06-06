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

	if strings.HasPrefix(hexsum, "Q1") {
		// This is nonstandard but something we did at one point, handle it.
		// In other contexts, this Q1 prefix means "this is sha1 not md5".
		b64 := strings.TrimPrefix(hexsum, "Q1")

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
