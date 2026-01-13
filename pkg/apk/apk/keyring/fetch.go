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

package keyring

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"path/filepath"

	"github.com/charmbracelet/log"
)

func fetchKeyFromURL(ctx context.Context, fetcher Fetcher, keyURL string, authenticated bool) (Key, error) {
	log.Debugf("installing key %v", keyURL)

	resp, err := fetcher(ctx, keyURL, authenticated)
	if err != nil {
		return Key{}, fmt.Errorf("failed to fetch apk key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Key{}, fmt.Errorf("failed to fetch apk key from %s: http response indicated error code: %d", keyURL, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return Key{}, fmt.Errorf("failed to read apk key response: %w", err)
	}

	basefilenameEscape := filepath.Base(keyURL)
	basefilename, err := url.PathUnescape(basefilenameEscape)
	if err != nil {
		return Key{}, fmt.Errorf("failed to unescape key filename %s: %w", basefilenameEscape, err)
	}

	return Key{
		ID:    basefilename,
		Bytes: data,
		URL:   keyURL,
	}, nil
}
