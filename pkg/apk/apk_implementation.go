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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"go.lsp.dev/uri"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/exec"
	"chainguard.dev/apko/pkg/options"
)

var fileSystem = []struct {
	name  string
	perm  os.FileMode
	isDir bool
}{

	// Directories
	{"dev", os.FileMode(0o755), true},
	{"etc/apk", os.FileMode(0o755), true},
	{"proc", os.FileMode(0o555), true},
	{"tmp", os.FileMode(0o1777), true},
	{"var/cache/misc/", os.FileMode(0o755), true},
	{"var/cache/apk/", os.FileMode(0o755), true},
	{"lib/apk/db/", os.FileMode(0o755), true},
	// Empty files that can be created
	{"lib/apk/db/installed", os.FileMode(0o644), false},
	{"lib/apk/db/lock", os.FileMode(0o600), false},
	{"lib/apk/db/scripts.tar", os.FileMode(0o644), false},
	{"lib/apk/db/trigger", os.FileMode(0o644), false},
	{"etc/apk/world", os.FileMode(0o644), false},
	{"etc/apk/arch", os.FileMode(0o644), false},
}

var deviceFiles = []struct {
	name  string
	perm  os.FileMode
	major uint32
	minor uint32
}{
	{"dev/console", os.FileMode(0o600), 5, 1},
	{"dev/null", os.FileMode(0o666), 1, 3},
	{"dev/random", os.FileMode(0o666), 1, 8},
	{"dev/urandom", os.FileMode(0o666), 1, 9},
	{"dev/zero", os.FileMode(0o666), 1, 5},
}

//counterfeiter:generate . apkImplementation

type apkImplementation interface {
	InitDB(*options.Options, exec.Executor) error
	LoadSystemKeyring(*options.Options, ...string) ([]string, error)
	InitKeyring(*options.Options, *types.ImageConfiguration) error
	InitWorld(*options.Options, *types.ImageConfiguration) error
	FixateWorld(*options.Options, *exec.Executor) error
	NormalizeScriptsTar(*options.Options) error
	InitRepositories(*options.Options, *types.ImageConfiguration) error
}

type apkDefaultImplementation struct{}

// Initialize the APK database for a given build context.  It is assumed that
// the build context itself is properly set up, and that `bc.Options.WorkDir` is set
// to the path of a working directory.
func (di *apkDefaultImplementation) InitDB(o *options.Options, e exec.Executor) error {
	o.Logger().Infof("initializing apk database")

	if err := initCreateFileSystem(o); err != nil {
		return fmt.Errorf("creating apk filesystem: %w", err)
	}

	if err := initCreateDeviceFiles(o); err != nil {
		return fmt.Errorf("creating device files: %w", err)
	}

	if err := initWriteScriptsTarball(o); err != nil {
		return fmt.Errorf("creating scripts tarball: %w", err)
	}
	return nil
}

func initCreateFileSystem(o *options.Options) error {
	// Create the skeleton directories
	for _, fileData := range fileSystem {
		if fileData.isDir {
			if err := os.MkdirAll(filepath.Join(o.WorkDir, fileData.name), fileData.perm); err != nil {
				return fmt.Errorf("creating directory: %w", err)
			}
		} else {
			if _, err := os.Create(filepath.Join(o.WorkDir, fileData.name)); err != nil {
				return fmt.Errorf("touching new file %s: %w", fileData.name, err)
			}
		}
		if err := os.Chmod(filepath.Join(o.WorkDir, fileData.name), fileData.perm); err != nil {
			return fmt.Errorf("chmodding %s: %w", fileData.name, err)
		}
	}

	// Write the arch file
	if err := os.WriteFile(
		filepath.Join(o.WorkDir, "etc/apk/arch"),
		[]byte(o.Arch.ToAPK()+"\n"), os.FileMode(0o644),
	); err != nil {
		return fmt.Errorf("writing arch file: %w", err)
	}
	return nil
}

// Creates the required device files in the apk filesystem
func initCreateDeviceFiles(o *options.Options) error {
	for _, devData := range deviceFiles {
		if err := unix.Mknod(
			filepath.Join(o.WorkDir, devData.name),
			syscall.S_IFCHR,
			int(unix.Mkdev(devData.major, devData.minor)),
		); err != nil {
			return fmt.Errorf("creating device file %s: %w", devData.name, err)
		}
		if err := os.Chmod(filepath.Join(o.WorkDir, devData.name), devData.perm); err != nil {
			return fmt.Errorf("changing device file permissions")
		}
	}
	return nil
}

// initWriteScriptsTarball Writes the empty script tarball
func initWriteScriptsTarball(o *options.Options) error {
	tarHeader, err := base64.StdEncoding.DecodeString(
		strings.Join(
			[]string{
				strings.Repeat(strings.Repeat("A", 76)+"\n", 17),
				strings.Repeat("A", 74), "==",
			}, "",
		),
	)
	if err != nil {
		return fmt.Errorf("decoding tarball header: %w", err)
	}
	if err := os.WriteFile(
		filepath.Join(o.WorkDir, "lib/apk/db/scripts.tar"),
		tarHeader, os.FileMode(0o644),
	); err != nil {
		return fmt.Errorf("writing scripts tarball: %w", err)
	}
	return nil
}

// LoadSystemKeyring returns the keys found in the system keyring
// directory by trying some common locations. These can be overridden
// by passing one or more directories as arguments.
func (di *apkDefaultImplementation) LoadSystemKeyring(o *options.Options, locations ...string) ([]string, error) {
	var ring []string
	if len(locations) == 0 {
		locations = []string{
			filepath.Join(DefaultSystemKeyRingPath, o.Arch.ToAPK()),
		}
	}
	for _, d := range locations {
		keyFiles, err := os.ReadDir(d)

		if errors.Is(err, os.ErrNotExist) {
			o.Logger().Warnf("%s doesn't exist, skipping...", d)
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
				o.Logger().Infof("%s has invalid extension (%s), skipping...", p, ext)
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
func (di *apkDefaultImplementation) InitKeyring(o *options.Options, ic *types.ImageConfiguration) (err error) {
	o.Logger().Infof("initializing apk keyring")

	if err := os.MkdirAll(filepath.Join(o.WorkDir, DefaultKeyRingPath),
		0o755); err != nil {
		return fmt.Errorf("failed to make keys dir: %w", err)
	}

	keyFiles := ic.Contents.Keyring

	if len(keyFiles) == 0 {
		keyFiles, err = di.LoadSystemKeyring(o)
		if err != nil {
			return fmt.Errorf("opening system keyring: %w", err)
		}
	}

	if len(o.ExtraKeyFiles) > 0 {
		o.Logger().Debugf("appending %d extra keys to keyring", len(o.ExtraKeyFiles))
		keyFiles = append(keyFiles, o.ExtraKeyFiles...)
	}

	var eg errgroup.Group

	for _, element := range keyFiles {
		element := element
		eg.Go(func() error {
			o.Logger().Debugf("installing key %v", element)

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
			if err := os.WriteFile(filepath.Join(o.WorkDir, "etc", "apk", "keys", filepath.Base(element)), data,
				0o644); err != nil {
				return fmt.Errorf("failed to write apk key: %w", err)
			}

			return nil
		})
	}

	return eg.Wait()
}

// Generates a specified /etc/apk/world file in the build context.
func (di *apkDefaultImplementation) InitWorld(o *options.Options, ic *types.ImageConfiguration) error {
	o.Logger().Infof("initializing apk world")

	data := strings.Join(ic.Contents.Packages, "\n")

	// #nosec G306 -- apk world must be publicly readable
	if err := os.WriteFile(filepath.Join(o.WorkDir, "etc", "apk", "world"),
		[]byte(data), 0o644); err != nil {
		return fmt.Errorf("failed to write apk world: %w", err)
	}

	return nil
}

// Force apk's resolver to re-resolve the requested dependencies in /etc/apk/world.
func (di *apkDefaultImplementation) FixateWorld(o *options.Options, e *exec.Executor) error {
	o.Logger().Infof("synchronizing with desired apk world")

	args := []string{
		"fix", "--root", o.WorkDir, "--no-scripts", "--no-cache",
		"--update-cache", "--arch", o.Arch.ToAPK(),
	}

	return e.Execute("apk", args...)
}

func (di *apkDefaultImplementation) NormalizeScriptsTar(o *options.Options) error {
	scriptsTar := filepath.Join(o.WorkDir, "lib", "apk", "db", "scripts.tar")

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
		header.AccessTime = o.SourceDateEpoch
		header.ModTime = o.SourceDateEpoch
		header.ChangeTime = o.SourceDateEpoch

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

// Generates a specified /etc/apk/repositories file in the build context.
func (di *apkDefaultImplementation) InitRepositories(o *options.Options, ic *types.ImageConfiguration) error {
	o.Logger().Infof("initializing apk repositories")

	data := strings.Join(ic.Contents.Repositories, "\n")

	if len(o.ExtraRepos) > 0 {
		// TODO(kaniini): not sure if the extra newline is actually needed
		data += "\n"
		data += strings.Join(o.ExtraRepos, "\n")
	}

	// #nosec G306 -- apk repositories must be publicly readable
	if err := os.WriteFile(filepath.Join(o.WorkDir, "etc", "apk", "repositories"),
		[]byte(data), 0o644); err != nil {
		return fmt.Errorf("failed to write apk repositories list: %w", err)
	}

	return nil
}
