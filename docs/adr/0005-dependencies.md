# ADR 0005: Dependency policy

## Context

genkan is a small, long-lived piece of infrastructure built with
`buildGoModule`. Every dependency is a `vendorHash` churn, a supply-chain
surface and code the maintainer does not read. The Go standard library covers
reverse proxying, static files, TLS, HTTP/2, logging and signals.

## Decision

Standard library by default. The following external modules are allowed; any
other addition requires a new ADR.

| Need | Module | Why not stdlib |
|---|---|---|
| TOML parsing | `github.com/pelletier/go-toml/v2` | No TOML in stdlib. `DisallowUnknownFields` turns a misspelled key in Nix-generated config into a validation error. |
| PROXY protocol v1/v2 (v1 milestone) | `github.com/pires/go-proxyproto` | Parsing v2 with TLVs plus a per-source policy (`REQUIRE` for trusted sources, `REJECT` otherwise) is ~150 lines to write and test; the library already implements exactly that. |

Explicitly stdlib: `net/http/httputil.ReverseProxy`, `http.FileServer`,
`crypto/tls`, `log/slog`, `os/signal`, sd_notify (a `net.DialUnix` write to
`NOTIFY_SOCKET`).

## Alternatives considered

- **Zero dependencies.** Writing a TOML parser is the only hard blocker; the
  PROXY protocol is feasible but not worth maintaining.
- **`github.com/BurntSushi/toml`.** Equivalent; `go-toml/v2` chosen for
  active maintenance and a direct `DisallowUnknownFields` option.
- **An ACME library** (`autocert`, lego, certmagic). Rejected: issuance is
  hanko's job (ADR 0004); genkan only reads files.

## Consequences

- `go.mod` stays readable; `vendorHash` changes rarely.
- Current API shape of `go-proxyproto` must be confirmed from its docs when
  the v1 milestone starts, not from memory.

## Status

Accepted, 2026-10-12.
