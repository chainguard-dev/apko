// Copyright 2022 Chainguard, Inc.
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

package build

import (
	"archive/tar"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"go.lsp.dev/uri"
	"golang.org/x/sync/errgroup"
)

var systemKeyringLocations = []string{"/etc/apk/keys/"}

// Programmatic wrapper around apk-tools.  For now, this is done with os.Exec(),
// but this has been designed so that we can port it easily to use libapk-go once
// it is ready.

// Initialize the APK database for a given build context.  It is assumed that
// the build context itself is properly set up, and that `bc.WorkDir` is set
// to the path of a working directory.
func (bc *Context) InitApkDB() error {
	log.Printf("initializing apk database")

	return bc.Execute("apk", "add", "--initdb", "--root", bc.WorkDir)
}

// loadSystemKeyring returns the keys found in the system keyring
// directory by trying some common locations. These can be overridden
// by passing one or more directories as arguments.
func (*Context) loadSystemKeyring(locations ...string) ([]string, error) {
	var ring []string
	if len(locations) == 0 {
		locations = systemKeyringLocations
	}
	for _, d := range locations {
		keyFiles, err := os.ReadDir(d)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, errors.Wrap(err, "reading keyring directory")
		}

		for _, f := range keyFiles {
			if filepath.Ext(f.Name()) == ".pub" {
				ring = append(ring, filepath.Join(d, f.Name()))
			}
		}
		if len(ring) > 0 {
			return ring, nil
		}
	}
	// Return an error since reading the system keyring is the last resort
	return nil, errors.New("no suitable keyring directory found")
}

// Installs the specified keys into the APK keyring inside the build context.
func (bc *Context) InitApkKeyring() (err error) {
	log.Printf("initializing apk keyring")

	if err := os.MkdirAll(filepath.Join(bc.WorkDir, "etc", "apk", "keys"),
		0755); err != nil {
		return errors.Wrap(err, "failed to make keys dir")
	}

	keyFiles := bc.ImageConfiguration.Contents.Keyring

	if len(keyFiles) == 0 {
		keyFiles, err = bc.loadSystemKeyring()
		if err != nil {
			return errors.Wrap(err, "opening system keyring")
		}
	}

	var eg errgroup.Group

	for _, element := range keyFiles {
		element := element
		eg.Go(func() error {
			log.Printf("installing key %v", element)

			// Normalize the element as a URI, so that local paths
			// are translated into file:// URLs, allowing them to be parsed
			// into a url.URL{}.
			asURI := uri.New(element)
			asURL, err := url.Parse(string(asURI))
			if err != nil {
				return errors.Wrap(err, "failed to parse key as URI")
			}

			var data []byte
			switch asURL.Scheme {
			case "file":
				data, err = os.ReadFile(element)
				if err != nil {
					return errors.Wrap(err, "failed to read apk key")
				}
			case "https":
				resp, err := http.Get(asURL.String())
				if err != nil {
					return errors.Wrap(err, "failed to fetch apk key")
				}
				defer resp.Body.Close()

				if resp.StatusCode < 200 || resp.StatusCode > 299 {
					return errors.New("failed to fetch apk key: http response indicated error")
				}

				data, err = io.ReadAll(resp.Body)
				if err != nil {
					return errors.Wrap(err, "failed to read apk key response")
				}
			default:
				return errors.Errorf("scheme %s not supported", asURL.Scheme)
			}

			// #nosec G306 -- apk keyring must be publicly readable
			if err := os.WriteFile(filepath.Join(bc.WorkDir, element), data,
				0644); err != nil {
				return errors.Wrap(err, "failed to write apk key")
			}

			return nil
		})
	}

	return eg.Wait()
}

// Generates a specified /etc/apk/repositories file in the build context.
func (bc *Context) InitApkRepositories() error {
	log.Printf("initializing apk repositories")

	data := strings.Join(bc.ImageConfiguration.Contents.Repositories, "\n")

	// #nosec G306 -- apk repositories must be publicly readable
	err := os.WriteFile(filepath.Join(bc.WorkDir, "etc", "apk", "repositories"),
		[]byte(data), 0644)
	if err != nil {
		return errors.Wrap(err, "failed to write apk repositories list")
	}

	return nil
}

// Generates a specified /etc/apk/world file in the build context.
func (bc *Context) InitApkWorld() error {
	log.Printf("initializing apk world")

	data := strings.Join(bc.ImageConfiguration.Contents.Packages, "\n")

	// #nosec G306 -- apk world must be publicly readable
	err := os.WriteFile(filepath.Join(bc.WorkDir, "etc", "apk", "world"),
		[]byte(data), 0644)
	if err != nil {
		return errors.Wrap(err, "failed to write apk world")
	}

	return nil
}

// Force apk's resolver to re-resolve the requested dependencies in /etc/apk/world.
func (bc *Context) FixateApkWorld() error {
	log.Printf("synchronizing with desired apk world")

	args := []string{"fix", "--root", bc.WorkDir, "--no-cache", "--update-cache"}
	if bc.UseProot {
		args = append(args, "--no-scripts")
	}

	return bc.Execute("apk", args...)
}

func (bc *Context) normalizeApkScriptsTar() error {
	scriptsTar := filepath.Join(bc.WorkDir, "lib", "apk", "db", "scripts.tar")

	f, err := os.Open(scriptsTar)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	defer f.Close()

	outfile, err := os.CreateTemp("", "apko-scripts-*.tar")
	if err != nil {
		return err
	}

	defer outfile.Close()

	tr := tar.NewReader(f)
	tw := tar.NewWriter(outfile)

	defer tw.Close()

	for {
		header, err := tr.Next()

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return err
		}

		// zero out timestamps for reproducibility
		header.AccessTime = bc.SourceDateEpoch
		header.ModTime = bc.SourceDateEpoch
		header.ChangeTime = bc.SourceDateEpoch

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// #nosec G110 -- scripts.tar is generated by apk
		if _, err := io.Copy(tw, tr); err != nil {
			return err
		}
	}

	return os.Rename(outfile.Name(), scriptsTar)
}
