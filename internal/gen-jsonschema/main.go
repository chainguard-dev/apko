package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/invopop/jsonschema"

	"chainguard.dev/apko/pkg/build/types"
)

var (
	outputFlag = flag.String("o", "", "output path")
)

func main() {
	flag.Parse()

	if *outputFlag == "" {
		log.Fatal("output path is required")
	}

	r := new(jsonschema.Reflector)
	if err := r.AddGoComments("chainguard.dev/apko/pkg/build", "../../pkg/build/types"); err != nil {
		log.Fatal(err)
	}
	schema := r.Reflect(types.ImageConfiguration{})

	// KeyEntry is a union — a URI string or a {name, content} object — which the
	// struct reflector can't express, so set it here rather than importing
	// invopop into the widely-used types package.
	keProps := jsonschema.NewProperties()
	keProps.Set("name", &jsonschema.Schema{Type: "string"})
	keProps.Set("content", &jsonschema.Schema{Type: "string"})
	schema.Definitions["KeyEntry"] = &jsonschema.Schema{
		OneOf: []*jsonschema.Schema{
			{Type: "string"},
			{Type: "object", Properties: keProps, Required: []string{"name", "content"}, AdditionalProperties: jsonschema.FalseSchema},
		},
	}

	b := new(bytes.Buffer)
	enc := json.NewEncoder(b)
	enc.SetIndent("", "  ")
	if err := enc.Encode(schema); err != nil {
		log.Fatal(err)
	}
	//nolint:gosec  // gosec wants us to use 0600, but making this globally readable is preferred.
	if err := os.WriteFile(*outputFlag, b.Bytes(), 0644); err != nil {
		log.Fatal(err)
	}
}
