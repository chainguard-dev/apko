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
	"fmt"
	"log"
	"os/exec"
)

func runCommand(cmd *exec.Cmd, logname string) error {
	log.Printf("running: %s", cmd)

	output, err := cmd.CombinedOutput()
	if output != nil {
		log.Printf("[%s] %s", logname, output)
	}
	if err != nil {
		return fmt.Errorf("failed to run %s: %w", cmd, err)
	}

	return nil
}

// TODO(kaniini): Add support for using qemu-binfmt here for multiarch.
func (bc *Context) ExecuteChroot(name string, arg ...string) error {
	var cmd *exec.Cmd

	if bc.UseProot {
		arg = append([]string{"-S", bc.WorkDir, name}, arg...)
		cmd = exec.Command("proot", arg...)
	} else {
		arg = append([]string{bc.WorkDir, name}, arg...)
		cmd = exec.Command("chroot", arg...)
	}

	return runCommand(cmd, name)
}

func (bc *Context) Execute(name string, arg ...string) error {
	logname := name

	if bc.UseProot {
		arg = append([]string{"-0", name}, arg...)
		name = "proot"
	}

	cmd := exec.Command(name, arg...)
	return runCommand(cmd, logname)
}
