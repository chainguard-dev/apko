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

package log

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

type Adapter struct {
	Out    io.Writer
	Fields Fields
	Level  Level
}

var concreteLogger = &logrus.Logger{
	Out:       os.Stderr,
	Formatter: &Formatter{},
	Hooks:     make(logrus.LevelHooks),
	Level:     logrus.InfoLevel,
}

func (a *Adapter) logf(level logrus.Level, format string, args ...interface{}) {
	e := concreteLogger.WithFields(logrus.Fields(a.Fields))
	e.Logger.SetLevel(logrus.Level(a.Level))
	e.Logger.Out = a.Out
	e.Logf(level, format, args...)
}

func (a *Adapter) exit(exitCode int) {
	cl := concreteLogger
	cl.Exit(exitCode)
}

func (a *Adapter) Debugf(fmt string, args ...interface{}) {
	a.logf(logrus.DebugLevel, fmt, args...)
}

func (a *Adapter) Fatalf(fmt string, args ...interface{}) {
	a.logf(logrus.FatalLevel, fmt, args...)
	a.exit(1)
}

func (a *Adapter) Infof(fmt string, args ...interface{}) {
	a.logf(logrus.InfoLevel, fmt, args...)
}

func (a *Adapter) Printf(fmt string, args ...interface{}) {
	a.logf(logrus.InfoLevel, fmt, args...)
}

func (a *Adapter) Warnf(fmt string, args ...interface{}) {
	a.logf(logrus.WarnLevel, fmt, args...)
}

func (a *Adapter) Errorf(fmt string, args ...interface{}) {
	a.logf(logrus.ErrorLevel, fmt, args...)
}

func (a *Adapter) SetLevel(level Level) {
	a.Level = level
}

func (a *Adapter) WithFields(fields Fields) Logger {
	out := *a
	out.Fields = fields
	return &out
}

func NewLogger(out io.Writer) Logger {
	return &Adapter{Out: out, Level: InfoLevel}
}

func DefaultLogger() Logger {
	return NewLogger(os.Stderr)
}
