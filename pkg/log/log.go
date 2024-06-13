// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import charmlog "github.com/charmbracelet/log"

// TODO: remove this once charmbracelet/log or log/slog supports a log level flag.
type CharmLogLevel charmlog.Level

func (l *CharmLogLevel) Set(s string) error {
	level, err := charmlog.ParseLevel(s)
	if err != nil {
		return err
	}
	*l = CharmLogLevel(level)
	return nil
}
func (l *CharmLogLevel) String() string { return charmlog.Level(*l).String() }
func (l *CharmLogLevel) Type() string   { return "string" }
