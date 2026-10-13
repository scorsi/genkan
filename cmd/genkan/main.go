// Command genkan is a reverse proxy for a Nix-managed homelab.
package main

import (
	"fmt"
	"os"
)

const usage = `usage: genkan <command> <config.toml>

commands:
  validate  check the config and exit
  run       serve the config until SIGTERM; SIGHUP reloads it
`

func main() {
	if len(os.Args) != 3 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "validate", "run":
		fmt.Fprintf(os.Stderr, "genkan %s: not implemented\n", os.Args[1])
		os.Exit(1)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}
