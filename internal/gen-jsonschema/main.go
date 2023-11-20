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
