// Copyright 2026 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tracing

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func cleanEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "OTEL_") {
			t.Setenv(key, "")
		}
	}
}

func startReceiver(t *testing.T, status int) *atomic.Int32 {
	t.Helper()
	requests := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/v1/traces" {
			t.Errorf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		if req.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Errorf("unexpected content type: %s", req.Header.Get("Content-Type"))
		}
		if _, err := io.Copy(io.Discard, req.Body); err != nil {
			t.Error(err)
		}
		requests.Add(1)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", server.URL)
	return requests
}

func TestDisabled(t *testing.T) {
	for _, tc := range []struct{ name, exporter, disabled string }{
		{name: "default"},
		{name: "none", exporter: "none"},
		{name: "sdk-disabled", exporter: "otlp", disabled: "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnvironment(t)
			t.Setenv("OTEL_TRACES_EXPORTER", tc.exporter)
			t.Setenv("OTEL_SDK_DISABLED", tc.disabled)
			requests := startReceiver(t, http.StatusOK)
			ctx := context.Background()
			previous := otel.GetTracerProvider()
			want := errors.New("command error")
			calls := 0
			got := Run(ctx, "test", "test command", func(seen context.Context) error {
				calls++
				if seen != ctx || otel.GetTracerProvider() != previous {
					t.Error("disabled tracing changed the context or provider")
				}
				return want
			})
			if got != want || calls != 1 { //nolint:errorlint // Check identity, including accidental wrapping.
				t.Fatalf("got (%v, %d calls), want original error and one call", got, calls)
			}
			if requests.Load() != 0 {
				t.Error("disabled tracing sent an OTLP request")
			}
		})
	}
}

func TestExport(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		commandError, reject bool
	}{
		{name: "success"},
		{name: "command-error", commandError: true},
		{name: "export-error", reject: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnvironment(t)
			t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
			// Exercise the default transport without a protocol override.
			status := http.StatusOK
			if tc.reject {
				status = http.StatusBadRequest
			}
			requests := startReceiver(t, status)
			previous := otel.GetTracerProvider()
			recorder := tracetest.NewSpanRecorder()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var want error
			if tc.commandError {
				want = errors.New("command failed")
			}
			got := Run(ctx, "test", "test command", func(ctx context.Context) error {
				provider, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider)
				if !ok {
					t.Fatal("tracing did not install an SDK provider")
				}
				// Observe our span lifecycle without decoding or testing OTLP serialization.
				provider.RegisterSpanProcessor(recorder)
				_, child := otel.Tracer("existing-library").Start(ctx, "existing child")
				child.End()
				cancel() // A canceled command context must not prevent the final export.
				return want
			})
			if got != want { //nolint:errorlint // Telemetry must preserve the exact command result.
				t.Fatalf("command result changed: got %v, want %v", got, want)
			}
			if requests.Load() == 0 {
				t.Error("no HTTP export before Run returned")
			}
			if otel.GetTracerProvider() != previous {
				t.Error("provider was not restored")
			}
			spans := recorder.Ended()
			if len(spans) != 2 {
				t.Fatalf("got %d spans, want root and existing child", len(spans))
			}
			var root, child sdktrace.ReadOnlySpan
			for _, span := range spans {
				switch span.Name() {
				case "test command":
					root = span
				case "existing child":
					child = span
				}
			}
			if root == nil || child == nil {
				t.Fatal("root or child missing")
			}
			if root.Parent().IsValid() || child.Parent().SpanID() != root.SpanContext().SpanID() || child.SpanContext().TraceID() != root.SpanContext().TraceID() {
				t.Error("existing child is not linked to the command root")
			}
			code := codes.Unset
			if tc.commandError {
				code = codes.Error
			}
			if root.Status().Code != code {
				t.Errorf("root status = %v, want %v", root.Status().Code, code)
			}
		})
	}
}
