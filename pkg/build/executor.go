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
	"log"
	"os/exec"

	"github.com/pkg/errors"
)

func (bc *Context) Execute(name string, arg ...string) error {
	logname := name

	if bc.UseProot {
		arg = append([]string{"-0", name}, arg...)
		name = "proot"
	}

	cmd := exec.Command(name, arg...)
	log.Printf("running: %v", cmd.String())

	output, err := cmd.CombinedOutput()
	if output != nil {
		log.Printf("[%s] %s", logname, output)
	}
	if err != nil {
		return errors.Wrapf(err, "failed to run %s", name)
	}

	return nil
}
