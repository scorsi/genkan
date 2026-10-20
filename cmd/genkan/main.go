// Command genkan is a reverse proxy for a Nix-managed homelab.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/scorsi/genkan/internal/config"
	"github.com/scorsi/genkan/internal/logging"
	"github.com/scorsi/genkan/internal/metrics"
	"github.com/scorsi/genkan/internal/serve"
)

// version is set by the Nix build (-X main.version=…).
var version = "dev"

const usage = `usage: genkan <command> <config.toml>

commands:
  validate  check the config and exit
  run       serve the config until SIGTERM, re-read it on SIGHUP
`

func main() {
	if len(os.Args) != 3 || (os.Args[1] != "validate" && os.Args[1] != "run") {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	// Both commands log schema lines: `validate` also runs as the unit's ExecReload, so its output
	// lands in the unit's journal next to `run`'s (ADR 0008).
	level := new(slog.LevelVar) // a reload may change it
	log := logging.New(os.Stderr, level)
	cfg, warnings, err := config.Load(os.Args[2])
	for _, w := range warnings {
		log.Warn("", "event", "config-warning", "err", w)
	}
	if err != nil {
		log.Error("", "event", "config-invalid", "err", err.Error())
		os.Exit(1)
	}
	if os.Args[1] == "validate" {
		return
	}

	level.UnmarshalText([]byte(cfg.Log.Level))
	log.Info("", "event", "start", "version", version)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := serve.Run(ctx, os.Args[2], cfg, log, level, metrics.New(version)); err != nil {
		log.Error("", "event", "fatal", "err", err.Error())
		os.Exit(1)
	}
}
