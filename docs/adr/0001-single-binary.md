# ADR 0001: One binary for the homelab proxy and the public edge

## Context

genkan runs in two places. In the homelab it terminates TLS and
routes HTTP by hostname. On the public edge it must not hold private
keys: it reads the SNI of incoming TLS connections and forwards the raw TCP
stream over the kekkai overlay to the homelab, prefixing it with the PROXY
protocol so the client IP survives. It also forwards plain TCP ports (git
SSH) without SNI.

Both roles share listeners, PROXY protocol handling, TOML config and its
validation, SIGHUP reload, structured logging, systemd readiness and the Nix
module. Only the per-connection behaviour differs.

## Decision

A single `genkan` binary. The edge role is not a mode: it is a genkan instance
whose config contains only `tcp` routes (see ADR 0002). Nothing in the binary
knows it is "on the edge".

## Alternatives considered

- **A second lightweight binary for the edge.** Saves a few megabytes of a static
  Go binary on a VPS where that does not matter, and doubles the config
  parser, the Nix module, the test matrix and the release process.
- **Build tags to strip the L7 code from the edge build.** Two artifacts to
  test for no operational gain; a config without `http` routes already never
  executes that code.

## Consequences

- One flake package, one NixOS module, one release.
- A bug in the HTTP path ships to the edge but is not reachable there.
- The edge and the homelab instance must be upgraded in step only when the PROXY
  protocol or L4 behaviour changes; HTTP-only changes do not affect the edge.

## Status

Accepted, 2026-10-12.
