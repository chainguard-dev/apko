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
	"github.com/sirupsen/logrus"
)

type Fields map[string]interface{}

type Level uint32

const (
	DebugLevel = Level(logrus.DebugLevel)
	ErrorLevel = Level(logrus.ErrorLevel)
	InfoLevel  = Level(logrus.InfoLevel)
	WarnLevel  = Level(logrus.WarnLevel)
	FatalLevel = Level(logrus.FatalLevel)
)

type Logger interface {
	Fatalf(string, ...interface{})
	Errorf(string, ...interface{})
	Infof(string, ...interface{})
	Printf(string, ...interface{})
	Warnf(string, ...interface{})
	Debugf(string, ...interface{})
	SetLevel(level Level)
	WithFields(fields Fields) Logger
}
