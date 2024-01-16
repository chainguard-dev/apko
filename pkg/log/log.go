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
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/term"
)

// writerFromTarget returns a writer given a target specification.
func writerFromTarget(target string) (io.Writer, error) {
	switch target {
	case "builtin:stderr":
		return os.Stderr, nil
	case "builtin:stdout":
		return os.Stdout, nil
	case "builtin:discard":
		return io.Discard, nil
	default:
		if strings.Contains(target, "/") {
			parent := filepath.Dir(target)
			if err := os.MkdirAll(parent, 0o755); err != nil {
				return nil, err
			}
		}

		log.Println("writing log file to", target)
		out, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE, 0o644)
		if err != nil {
			return nil, err
		}

		return out, nil
	}
}

// writer returns a writer which writes to multiple target specifications.
func writer(targets []string) (io.Writer, error) {
	writers := []io.Writer{}

	if len(targets) == 1 {
		return writerFromTarget(targets[0])
	}

	for _, target := range targets {
		writer, err := writerFromTarget(target)
		if err != nil {
			return nil, err
		}

		writers = append(writers, writer)
	}

	return io.MultiWriter(writers...), nil
}

const (
	reset   = 0
	yellow  = 33
	magenta = 35
	gray    = 37
)

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

func levelToColor(r slog.Record) int {
	switch r.Level {
	case slog.LevelError:
		return magenta
	case slog.LevelWarn:
		return yellow
	default:
		return gray
	}
}

func levelEmoji(r slog.Record) string {
	switch r.Level {
	case slog.LevelError:
		return "❌ "
	case slog.LevelWarn:
		return "⚠️ "
	case slog.LevelInfo:
		return "ℹ️ "
	default:
		return "❕"
	}
}

func Handler(logPolicy []string, level slog.Level) slog.Handler {
	out, err := writer(logPolicy)
	if err != nil {
		log.Panic(err)
	}
	return &handler{out: out, level: level}
}

type handler struct {
	level slog.Level
	out   io.Writer
	attrs []slog.Attr

	mu sync.Mutex
}

func (h *handler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }
func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &handler{attrs: append(h.attrs, attrs...), out: h.out}
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.Enabled(ctx, r.Level) {
		return nil
	}

	var arch string
	for _, a := range h.attrs {
		if a.Key == "arch" {
			arch = a.Value.String()
			break
		}
	}
	if arch == "" {
		r.Attrs(func(s slog.Attr) bool {
			if s.Key == "arch" {
				arch = s.Value.String()
				return false
			}
			return true
		})
	}
	if arch != "" {
		fmt.Fprintf(h.out, "%s %s%-10s|%s %s%s%s\n", levelEmoji(r), color(h.out, levelToColor(r)), arch, color(h.out, reset), color(h.out, levelToColor(r)), r.Message, color(h.out, reset))
	} else {
		fmt.Fprintf(h.out, "%s %s%-10s|%s %s%s%s\n", levelEmoji(r), color(h.out, levelToColor(r)), "", color(h.out, reset), color(h.out, levelToColor(r)), r.Message, color(h.out, reset))
	}

	return nil
}

// This handler doesn't support groups.
// TODO(jason): Support groups.
func (h *handler) WithGroup(string) slog.Handler { return h }
