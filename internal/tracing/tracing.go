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

// Package tracing configures optional tracing for the executable, not library callers.
package tracing

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Run enables OTLP only when explicitly requested. Telemetry errors are reported
// through the OpenTelemetry error handler and never replace the command result.
func Run(ctx context.Context, serviceName, spanName string, run func(context.Context) error) (err error) {
	if os.Getenv("OTEL_TRACES_EXPORTER") != "otlp" || strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true") {
		return run(ctx)
	}

	res, setupErr := resource.New(ctx,
		resource.WithAttributes(attribute.String("service.name", serviceName)),
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
	)
	if setupErr != nil {
		otel.Handle(fmt.Errorf("initializing trace resource: %w", setupErr))
		return run(ctx)
	}
	exporter, setupErr := newExporter(ctx)
	if setupErr != nil {
		otel.Handle(fmt.Errorf("initializing OTLP tracing: %w", setupErr))
		return run(ctx)
	}

	provider := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(exporter))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	defer otel.SetTracerProvider(previous)
	ctx, span := provider.Tracer(serviceName).Start(ctx, spanName)
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
		// The command may have canceled its context. Bound shutdown independently and
		// complete it before the executable calls os.Exit on a command error.
		flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if flushErr := provider.Shutdown(flushCtx); flushErr != nil {
			otel.Handle(fmt.Errorf("shutting down OTLP tracing: %w", flushErr))
		}
	}()
	return run(ctx)
}

func newExporter(ctx context.Context) (sdktrace.SpanExporter, error) {
	protocol := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
	if protocol == "" {
		protocol = os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}
	switch protocol {
	case "", "grpc":
		return otlptracegrpc.New(ctx)
	case "http/protobuf":
		return otlptracehttp.New(ctx)
	default:
		return nil, fmt.Errorf("unsupported OTLP protocol %q (use grpc or http/protobuf)", protocol)
	}
}
