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

package apk

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"go.lsp.dev/uri"
	"golang.org/x/sync/errgroup"
)

// Programmatic wrapper around apk-tools.  For now, this is done with os.Exec(),
// but this has been designed so that we can port it easily to use libapk-go once
// it is ready.

// Initialize the APK database for a given build context.  It is assumed that
// the build context itself is properly set up, and that `bc.WorkDir` is set
// to the path of a working directory.
func (ab *apkBuilder) InitApkDB() error {
	ab.Log.Printf("initializing apk database")

	return ab.executor.Execute("apk", "add", "--initdb", "--arch", ab.Arch.ToAPK(), "--root", ab.WorkDir)
}

// loadSystemKeyring returns the keys found in the system keyring
// directory by trying some common locations. These can be overridden
// by passing one or more directories as arguments.
func (ab *apkBuilder) loadSystemKeyring(locations ...string) ([]string, error) {
	var ring []string
	if len(locations) == 0 {
		locations = []string{
			filepath.Join("/usr/share/apk/keys/", ab.Arch.ToAPK()),
		}
	}
	for _, d := range locations {
		keyFiles, err := os.ReadDir(d)

		if errors.Is(err, os.ErrNotExist) {
			ab.Log.Printf("%s doesn't exist, skipping...", d)
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("reading keyring directory: %w", err)
		}

		for _, f := range keyFiles {
			ext := filepath.Ext(f.Name())
			p := filepath.Join(d, f.Name())

			if ext == ".pub" {
				ring = append(ring, p)
			} else {
				ab.Log.Printf("%s has invalid extension (%s), skipping...", p, ext)
			}
		}
	}
	if len(ring) > 0 {
		return ring, nil
	}
	// Return an error since reading the system keyring is the last resort
	return nil, errors.New("no suitable keyring directory found")
}

// Installs the specified keys into the APK keyring inside the build context.
func (ab *apkBuilder) InitApkKeyring() (err error) {
	ab.Log.Printf("initializing apk keyring")

	if err := os.MkdirAll(filepath.Join(ab.WorkDir, "etc", "apk", "keys"),
		0755); err != nil {
		return fmt.Errorf("failed to make keys dir: %w", err)
	}

	keyFiles := ab.ImageConfiguration.Contents.Keyring

	if len(keyFiles) == 0 {
		keyFiles, err = ab.loadSystemKeyring()
		if err != nil {
			return fmt.Errorf("opening system keyring: %w", err)
		}
	}

	if len(ab.ExtraKeyFiles) > 0 {
		ab.Log.Printf("appending %d extra keys to keyring", len(ab.ExtraKeyFiles))
		keyFiles = append(keyFiles, ab.ExtraKeyFiles...)
	}

	var eg errgroup.Group

	for _, element := range keyFiles {
		element := element
		eg.Go(func() error {
			ab.Log.Printf("installing key %v", element)

			// Normalize the element as a URI, so that local paths
			// are translated into file:// URLs, allowing them to be parsed
			// into a url.URL{}.
			var asURI uri.URI
			if strings.HasPrefix(element, "https://") {
				asURI, _ = uri.Parse(element)
			} else {
				asURI = uri.New(element)
			}
			asURL, err := url.Parse(string(asURI))
			if err != nil {
				return fmt.Errorf("failed to parse key as URI: %w", err)
			}

			var data []byte
			switch asURL.Scheme {
			case "file":
				data, err = os.ReadFile(element)
				if err != nil {
					return fmt.Errorf("failed to read apk key: %w", err)
				}
			case "https":
				resp, err := http.Get(asURL.String())
				if err != nil {
					return fmt.Errorf("failed to fetch apk key: %w", err)
				}
				defer resp.Body.Close()

				if resp.StatusCode < 200 || resp.StatusCode > 299 {
					return errors.New("failed to fetch apk key: http response indicated error")
				}

				data, err = io.ReadAll(resp.Body)
				if err != nil {
					return fmt.Errorf("failed to read apk key response: %w", err)
				}
			default:
				return fmt.Errorf("scheme %s not supported", asURL.Scheme)
			}

			// #nosec G306 -- apk keyring must be publicly readable
			if err := os.WriteFile(filepath.Join(ab.WorkDir, "etc", "apk", "keys", filepath.Base(element)), data,
				0644); err != nil {
				return fmt.Errorf("failed to write apk key: %w", err)
			}

			return nil
		})
	}

	return eg.Wait()
}

// Generates a specified /etc/apk/repositories file in the build context.
func (ab *apkBuilder) InitApkRepositories() error {
	ab.Log.Printf("initializing apk repositories")

	data := strings.Join(ab.ImageConfiguration.Contents.Repositories, "\n")

	if len(ab.ExtraRepos) > 0 {
		// TODO(kaniini): not sure if the extra newline is actually needed
		data += "\n"
		data += strings.Join(ab.ExtraRepos, "\n")
	}

	// #nosec G306 -- apk repositories must be publicly readable
	if err := os.WriteFile(filepath.Join(ab.WorkDir, "etc", "apk", "repositories"),
		[]byte(data), 0644); err != nil {
		return fmt.Errorf("failed to write apk repositories list: %w", err)
	}

	return nil
}

// Generates a specified /etc/apk/world file in the build context.
func (ab *apkBuilder) InitApkWorld() error {
	ab.Log.Printf("initializing apk world")

	data := strings.Join(ab.ImageConfiguration.Contents.Packages, "\n")

	// #nosec G306 -- apk world must be publicly readable
	if err := os.WriteFile(filepath.Join(ab.WorkDir, "etc", "apk", "world"),
		[]byte(data), 0644); err != nil {
		return fmt.Errorf("failed to write apk world: %w", err)
	}

	return nil
}

// Force apk's resolver to re-resolve the requested dependencies in /etc/apk/world.
func (ab *apkBuilder) FixateApkWorld() error {
	ab.Log.Printf("synchronizing with desired apk world")

	args := []string{"fix", "--root", ab.WorkDir, "--no-scripts", "--no-cache", "--update-cache", "--arch", ab.Arch.ToAPK()}

	return ab.executor.Execute("apk", args...)
}

func (ab *apkBuilder) normalizeApkScriptsTar() error {
	scriptsTar := filepath.Join(ab.WorkDir, "lib", "apk", "db", "scripts.tar")

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
		header.AccessTime = ab.SourceDateEpoch
		header.ModTime = ab.SourceDateEpoch
		header.ChangeTime = ab.SourceDateEpoch

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
