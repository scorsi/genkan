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
	"github.com/scorsi/genkan/internal/serve"
)

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
	cfg, warnings, err := config.Load(os.Args[2])
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if os.Args[1] == "validate" {
		return
	}

	level := new(slog.LevelVar) // a reload may change it
	level.UnmarshalText([]byte(cfg.Log.Level))
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := serve.Run(ctx, os.Args[2], cfg, log, level); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}
