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

package impl

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"gitlab.alpinelinux.org/alpine/go/repository"
	"go.lsp.dev/uri"
)

// GetRepositoryIndexes returns the indexes for the named repositories, keys and archs.
// The signatures for each index are verified unless ignoreSignatures is set to true.
// The key-value pairs in the map for `keys` are the name of the key and the contents of the key.
// The name is just indicative. If it finds a match, it will use it. Else, it will try all keys.
func GetRepositoryIndexes(repos []string, keys map[string][]byte, arch string, options ...IndexOption) (indexes []*namedRepositoryWithIndex, err error) {
	opts := &indexOpts{}
	for _, opt := range options {
		opt(opts)
	}
	r := regexp.MustCompile(`^\.SIGN\.RSA\.(.*\.rsa\.pub)$`)

	for _, repo := range repos {
		// does it start with a pin?
		var (
			repoName string
			repoURL  = repo
		)
		if strings.HasPrefix(repo, "@") {
			// it's a pinned repository, get the name
			parts := strings.Fields(repo)
			if len(parts) < 2 {
				return nil, errors.New("invalid repository line")
			}
			repoName = parts[0][1:]
			repoURL = parts[1]
		}

		repoBase := fmt.Sprintf("%s/%s", repoURL, arch)
		u := fmt.Sprintf("%s/%s", repoBase, indexFilename)

		// Normalize the repo as a URI, so that local paths
		// are translated into file:// URLs, allowing them to be parsed
		// into a url.URL{}.
		var (
			b     []byte
			asURI uri.URI
		)
		if strings.HasPrefix(u, "https://") {
			asURI, _ = uri.Parse(u)
		} else {
			asURI = uri.New(u)
		}
		asURL, err := url.Parse(string(asURI))
		if err != nil {
			return nil, fmt.Errorf("failed to parse repo as URI: %w", err)
		}

		switch asURL.Scheme {
		case "file":
			b, err = os.ReadFile(u)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return nil, fmt.Errorf("failed to read repository %s: %w", u, err)
				}
				continue
			}
		case "https":
			client := opts.httpClient
			if client == nil {
				client = &http.Client{}
			}
			res, err := client.Get(asURL.String()) // nolint:gosec // we know what we are doing here
			if err != nil {
				return nil, fmt.Errorf("unable to get repository index at %s: %w", u, err)
			}
			defer res.Body.Close()
			buf := bytes.NewBuffer(nil)
			if _, err := io.Copy(buf, res.Body); err != nil {
				return nil, fmt.Errorf("unable to read repository index at %s: %w", u, err)
			}
			b = buf.Bytes()
		default:
			return nil, fmt.Errorf("repository scheme %s not supported", asURL.Scheme)
		}

		// validate the signature
		if !opts.ignoreSignatures {
			buf := bytes.NewReader(b)
			gzipReader, err := gzip.NewReader(buf)
			if err != nil {
				return nil, fmt.Errorf("unable to create gzip reader for repository index: %w", err)
			}
			// set multistream to false, so we can read each part separately;
			// the first part is the signature, the second is the index, which should be
			// verified.
			gzipReader.Multistream(false)
			defer gzipReader.Close()

			tarReader := tar.NewReader(gzipReader)

			// read the signature
			signatureFile, err := tarReader.Next()
			if err != nil {
				return nil, fmt.Errorf("failed to read signature from repository index: %w", err)
			}
			matches := r.FindStringSubmatch(signatureFile.Name)
			if len(matches) != 2 {
				return nil, fmt.Errorf("failed to find key name in signature file name: %s", signatureFile.Name)
			}
			signature, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, fmt.Errorf("failed to read signature from repository index: %w", err)
			}
			// with multistream false, we should read the next one
			if _, err := tarReader.Next(); err != nil && !errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("unexpected error reading from tgz: %w", err)
			}
			// we now have the signature bytes and name, get the contents of the rest;
			// this should be everything else in the raw gzip file as is.
			allBytes := len(b)
			unreadBytes := buf.Len()
			readBytes := allBytes - unreadBytes
			indexData := b[readBytes:]

			indexDigest, err := HashData(indexData)
			if err != nil {
				return nil, err
			}
			// now we can check the signature
			if keys == nil {
				return nil, fmt.Errorf("no keys provided to verify signature")
			}
			var verified bool
			keyData, ok := keys[matches[1]]
			if ok {
				if err := RSAVerifySHA1Digest(indexDigest, signature, keyData); err != nil {
					verified = false
				}
			}
			if !verified {
				for _, keyData := range keys {
					if err := RSAVerifySHA1Digest(indexDigest, signature, keyData); err == nil {
						verified = true
						break
					}
				}
			}
			if !verified {
				return nil, fmt.Errorf("no key found to verify signature for keyfile %s; tried all other keys as well", matches[1])
			}

			// with a valid signature, convert it to an ApkIndex
			index, err := repository.IndexFromArchive(io.NopCloser(bytes.NewReader(b)))
			if err != nil {
				return nil, fmt.Errorf("unable to read convert repository index bytes to index struct at %s: %w", u, err)
			}
			repoRef := repository.Repository{Uri: repoBase}
			indexes = append(indexes, NewNamedRepositoryWithIndex(repoName, repoRef.WithIndex(index)))
		}
	}
	return indexes, nil
}

type indexOpts struct {
	ignoreSignatures bool
	httpClient       *http.Client
}
type IndexOption func(*indexOpts)

func WithIgnoreSignatures(ignoreSignatures bool) IndexOption {
	return func(o *indexOpts) {
		o.ignoreSignatures = ignoreSignatures
	}
}

func WithHTTPClient(c *http.Client) IndexOption {
	return func(o *indexOpts) {
		o.httpClient = c
	}
}
