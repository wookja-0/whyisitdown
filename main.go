// Command whyisitdown diagnoses why a URL is not reachable, one protocol layer
// at a time.
package main

import (
	"os"

	"github.com/wookja-0/whyisitdown/cmd"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(cmd.Execute(version, os.Args[1:], os.Stdout, os.Stderr))
}
