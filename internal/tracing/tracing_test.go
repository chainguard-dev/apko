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
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	collector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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
			t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
			r := startReceiver(t, "http/protobuf", false)
			ctx := context.Background()
			previous := otel.GetTracerProvider()
			want := errors.New("command error")
			calls := 0
			got := Run(ctx, "test", "test command", func(seen context.Context) error {
				calls++
				if seen != ctx {
					t.Error("disabled tracing changed the command context")
				}
				if otel.GetTracerProvider() != previous {
					t.Error("disabled tracing replaced the provider")
				}
				return want
			})
			if got != want || calls != 1 { //nolint:errorlint // Check identity, including accidental wrapping.
				t.Fatalf("got (%v, %d calls), want original error and one call", got, calls)
			}
			if len(r.requests) != 0 {
				t.Error("disabled tracing sent an OTLP request")
			}
		})
	}
}

type receiver struct {
	collector.UnimplementedTraceServiceServer
	requests chan *collector.ExportTraceServiceRequest
	reject   bool
}

func (r *receiver) Export(_ context.Context, req *collector.ExportTraceServiceRequest) (*collector.ExportTraceServiceResponse, error) {
	r.requests <- req
	if r.reject {
		return nil, status.Error(grpccodes.InvalidArgument, "test rejection")
	}
	return &collector.ExportTraceServiceResponse{}, nil
}

func startReceiver(t *testing.T, protocol string, reject bool) *receiver {
	t.Helper()
	r := &receiver{requests: make(chan *collector.ExportTraceServiceRequest, 8), reject: reject}
	if protocol == "grpc" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := grpc.NewServer()
		collector.RegisterTraceServiceServer(server, r)
		go func() { _ = server.Serve(listener) }()
		t.Cleanup(server.Stop)
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://"+listener.Addr().String())
	} else {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path != "/v1/traces" {
				t.Errorf("unexpected path %s", req.URL.Path)
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			data := new(collector.ExportTraceServiceRequest)
			if err := proto.Unmarshal(body, data); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			r.requests <- data
			if reject {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/x-protobuf")
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", server.URL)
	}
	return r
}

func TestExport(t *testing.T) {
	for _, tc := range []struct{ name, protocol, generic, specific string }{
		{name: "default-grpc", protocol: "grpc"},
		{name: "grpc", protocol: "grpc", generic: "grpc"},
		{name: "http", protocol: "http/protobuf", generic: "http/protobuf"},
		{name: "trace-protocol-override", protocol: "http/protobuf", generic: "invalid", specific: "http/protobuf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, failed := range []bool{false, true} {
				name := "success"
				if failed {
					name = "command-error"
				}
				t.Run(name, func(t *testing.T) {
					cleanEnvironment(t)
					t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
					t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", tc.generic)
					t.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", tc.specific)
					t.Setenv("OTEL_SERVICE_NAME", "configured-service")
					t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "test.case=export")
					r := startReceiver(t, tc.protocol, false)
					previous := otel.GetTracerProvider()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					var want error
					if failed {
						want = errors.New("command failed")
					}
					got := Run(ctx, "test", "test command", func(ctx context.Context) error {
						_, child := otel.Tracer("existing-library").Start(ctx, "existing child")
						child.End()
						cancel() // Shutdown must still export after the command context is canceled.
						return want
					})
					if got != want { //nolint:errorlint // Return the original command error, not a wrapper.
						t.Fatalf("command result changed: got %v, want %v", got, want)
					}
					if otel.GetTracerProvider() != previous {
						t.Error("provider was not restored")
					}
					var spans []*tracepb.Span
					for len(r.requests) > 0 {
						req := <-r.requests
						for _, resourceSpans := range req.ResourceSpans {
							attrs := map[string]string{}
							for _, attr := range resourceSpans.Resource.Attributes {
								attrs[attr.Key] = attr.Value.GetStringValue()
							}
							if attrs["service.name"] != "configured-service" || attrs["test.case"] != "export" {
								t.Errorf("resource attributes: %v", attrs)
							}
							for _, scope := range resourceSpans.ScopeSpans {
								spans = append(spans, scope.Spans...)
							}
						}
					}
					if len(spans) != 2 {
						t.Fatalf("got %d spans, want root and existing child", len(spans))
					}
					var root, child *tracepb.Span
					for _, span := range spans {
						switch span.Name {
						case "test command":
							root = span
						case "existing child":
							child = span
						}
					}
					if root == nil || child == nil {
						t.Fatal("root or child missing")
					}
					if !bytes.Equal(root.TraceId, child.TraceId) || !bytes.Equal(root.SpanId, child.ParentSpanId) {
						t.Error("existing child is not linked to command root")
					}
					if failed && root.Status.GetCode() != tracepb.Status_STATUS_CODE_ERROR {
						t.Error("command error not recorded on root")
					}
					if !failed && root.Status.GetCode() != tracepb.Status_STATUS_CODE_UNSET {
						t.Error("successful root has error status")
					}
				})
			}
		})
	}
}

func TestTelemetryFailurePreservesCommandResult(t *testing.T) {
	for _, mode := range []string{"initialization", "export"} {
		t.Run(mode, func(t *testing.T) {
			cleanEnvironment(t)
			t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
			if mode == "initialization" {
				t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "invalid")
			} else {
				t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
				startReceiver(t, "http/protobuf", true)
			}
			var mu sync.Mutex
			var reported []error
			previous := otel.GetErrorHandler()
			otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) { mu.Lock(); defer mu.Unlock(); reported = append(reported, err) }))
			t.Cleanup(func() { otel.SetErrorHandler(previous) })
			for _, want := range []error{nil, errors.New("original build failure")} {
				calls := 0
				if got := Run(context.Background(), "test", "test command", func(ctx context.Context) error {
					calls++
					if mode == "export" && !trace.SpanContextFromContext(ctx).IsValid() {
						t.Error("tracing did not start")
					}
					return want
				}); got != want || calls != 1 { //nolint:errorlint // Telemetry must not replace or wrap the command result.
					t.Fatalf("got (%v, %d calls), want original result and one call", got, calls)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if len(reported) == 0 {
				t.Error("telemetry failure was not reported")
			}
		})
	}
}
