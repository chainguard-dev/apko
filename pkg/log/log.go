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

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/term"
)

const (
	reset   = 0
	red     = 31
	green   = 32
	yellow  = 33
	blue    = 34
	magenta = 35
	cyan    = 36
	gray    = 37
)

// A Formatter is a formatter that can be set on a logrus object to
// apply our formatting policies.
type Formatter struct {
	logrus.Formatter
}

func isTerminal(w io.Writer) bool {
	switch v := w.(type) {
	case *os.File:
		return term.IsTerminal(int(v.Fd()))
	default:
		return false
	}
}

func color(w io.Writer, color int) string {
	if !isTerminal(w) {
		return ""
	}

	return fmt.Sprintf("\x1b[%dm", color)
}

func levelToColor(entry *logrus.Entry) int {
	switch entry.Level {
	case logrus.PanicLevel, logrus.FatalLevel:
		return red
	case logrus.ErrorLevel:
		return magenta
	case logrus.WarnLevel:
		return yellow
	case logrus.InfoLevel:
		return cyan
	default:
		return gray
	}
}

func levelEmoji(entry *logrus.Entry) string {
	switch entry.Level {
	case logrus.PanicLevel, logrus.FatalLevel:
		return "🛑 "
	case logrus.ErrorLevel:
		return "❌ "
	case logrus.WarnLevel:
		return "⚠️ "
	case logrus.InfoLevel:
		return "ℹ️ "
	default:
		return "❕ "
	}
}

// Format formats a logrus entry according to our formatting policies.
func (f *Formatter) Format(entry *logrus.Entry) ([]byte, error) {
	b := &bytes.Buffer{}
	out := entry.Logger.Out
	message := strings.TrimSuffix(entry.Message, "\n")

	if arch, ok := entry.Data["arch"]; ok {
		fmt.Fprintf(b, "%s %s%-10s|%s %s", levelEmoji(entry), color(out, levelToColor(entry)), arch, color(out, reset), message)
	} else {
		fmt.Fprintf(b, "%s %s%-10s|%s %s", levelEmoji(entry), color(out, levelToColor(entry)), "", color(out, reset), message)
	}

	b.WriteByte('\n')

	return b.Bytes(), nil
}
