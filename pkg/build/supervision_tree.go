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
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func (bc *Context) CreateSupervisionDirectory(name string) (string, error) {
	svcdir := filepath.Join(bc.WorkDir, "sv", name)
	log.Printf("  supervision dir: %s", svcdir)

	err := os.MkdirAll(svcdir, 0755)
	if err != nil {
		return svcdir, fmt.Errorf("could not make supervision directory: %w", err)
	}

	return svcdir, nil
}

func (bc *Context) WriteSupervisionTemplate(svcdir string, command string) error {
	file, err := os.Create(filepath.Join(svcdir, "run"))
	if err != nil {
		return fmt.Errorf("could not create runfile: %w", err)
	}
	defer file.Close()

	err = os.Chmod(file.Name(), 0755)
	if err != nil {
		return fmt.Errorf("could not set permissions on runfile: %w", err)
	}

	fmt.Fprintf(file, "#!/bin/execlineb\n%s\n", command)

	return nil
}

func (bc *Context) WriteSupervisionServiceSimple(name string, command string) error {
	log.Printf("simple service: %s => %s", name, command)

	svcdir, err := bc.CreateSupervisionDirectory(name)
	if err != nil {
		return err
	}

	err = bc.WriteSupervisionTemplate(svcdir, command)
	if err != nil {
		return err
	}

	return nil
}

func (bc *Context) WriteSupervisionTree() error {
	log.Printf("generating supervision tree")

	// generate the leaves
	for service, descriptor := range bc.ImageConfiguration.Entrypoint.Services {
		service, ok := service.(string)
		if !ok {
			return errors.New("service name is not string")
		}

		if svccmd, ok := descriptor.(string); ok {
			err := bc.WriteSupervisionServiceSimple(service, svccmd)
			if err != nil {
				return err
			}
		} else {
			return errors.New("complex services are not yet supported")
		}
	}

	return nil
}
