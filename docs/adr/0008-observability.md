# ADR 0008: Observability: schema logs on stderr, loopback /metrics, journald rate limit

## Context

The homelab's observability stack collects every service's journal lines (hikyaku, stored by
nisshi) and scrapes every service's `/metrics` (stored by masu). Both stores define a contract
that each service must meet, checked by their own validators: nisshi's log schema v1
(`docs/log-schema.md`, nisshi ADR 0009 "How services write logs") and masu's metric convention
(`docs/metric-convention.md`). A line that fails the schema is stored as `unparsed`; a scrape
that breaks the convention is refused. genkan logs per request, so it is also one of the two
services that can flood the journal.

Until now genkan wrote slog's default JSON (local time, trailing zeros dropped, `msg` as the
event name) and net/http wrote its own errors as free text. It exposed no metrics; the
milestones listed an admin `/metrics` listener as a v1+ proposal.

## Decision

**Logs.** Every line genkan writes on stderr, in both commands, is a schema v1 object:

- `log/slog` with the reference `ReplaceAttr` of nisshi's log-schema (`internal/logging`):
  `v:1`, UTC `ts` with exactly 9 fractional digits, lowercase `level`, `msg` dropped when empty,
  `event` an attribute in kebab-case. `err` only at `warn` or `error`. No reserved field.
- `request`, one per request when the response completes: `listener`, `route` (configured
  name, `-` when no route matched), `client`, `method`, `host`, `path` (no query string),
  `proto`, `tls` (`1.3`, `-` without TLS), `status`, `bytes` (response body bytes sent),
  `dur_us`, and `user_agent` (milestone v0.1). Written when `log.access` is true.
- `upstream-error` (warn): the backend failed before the response started; `listener`,
  `route`, `err`. A client that went away is not one.
- net/http's and httputil's own error lines go through a `*log.Logger` adapter into slog as
  warn lines with the line as `err`: `tls-handshake-error` for net/http's
  `http: TLS handshake error` lines (the only hook it offers), `http-error` for the rest of
  the server's lines, `proxy-error` for ReverseProxy's.
- Lifecycle events: `start`, `listening`, `metrics-listening`, `listener-closed`,
  `listener-stopped`, `reloaded`, `reload-failed`, `config-warning`, `config-invalid`,
  `certificate-mismatch`, `sd-notify-failed`, `fatal`.
- `genkan validate` writes the same schema lines: it also runs as the unit's `ExecReload`, so
  its output lands in genkan's journal.

**Metrics.** `GET /metrics` on `[metrics] listen` (TOML, docs/config.md), set by the module
option `services.genkan.metrics.listen` (default `null`, no listener). Loopback only:
`127.0.0.1:<port>` or `[::1]:<port>`, enforced by `genkan validate` and asserted by the module.
Hand-written Prometheus text 0.0.4 (`internal/metrics`), no client library (ADR 0005):

| Metric | Labels |
|---|---|
| `genkan_build_info` (gauge, 1) | `version` (set by the Nix build) |
| `genkan_requests_total` | `listener`, `route`, `method` (GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS, CONNECT, TRACE, else `other`), `code` (`2xx`…) |
| `genkan_request_duration_seconds` (histogram, buckets 0.01, 0.05, 0.25, 1, 5 s) | `listener`, `route` |
| `genkan_response_bytes_total` | `listener`, `route` |
| `genkan_upstream_errors_total` | `route` |
| `genkan_tls_handshake_errors_total` | `listener` |
| `genkan_certificate_expiry_timestamp_seconds` (gauge, leaf NotAfter) | `certificate` |

Labels are configured names or closed sets only; host, path and client go to logs. Series are
created on first use and never reset on reload. The budget: 8 histogram series plus at most a
few request series per listener × route pair actually used, under the convention's 500 for the
homelab's tens of routes. No Go runtime metrics (optional in the convention; nothing reads them).

The metrics listener is bound once, at start, before `READY=1`; a reload does not move it.
The module adds `metrics.listen` to the unit's `restartTriggers`, so a change restarts genkan
while every other config change still reloads.

**Rate limit.** The module sets `LogRateLimitIntervalSec=30s` and `LogRateLimitBurst=30000` as
`mkDefault` (nisshi ADR 0009): 1000 lines/s sustained before journald drops, and hikyaku counts
what it dropped. Not disabled.

**Tests.** Go unit tests check the logger (9-digit UTC `ts`, fields, empty `msg` dropped), the
`request` and `upstream-error` lines, the handshake-error adapter, and the exact exposition.
The NixOS VM test pipes `journalctl _SYSTEMD_UNIT=genkan.service -o cat` into
`nisshi validate --logs` after asserting the expected `request` lines exist (empty input is
valid), and runs `masu validate --metrics` on the live endpoint and checks that
`genkan_requests_total` moves with a request. nisshi and masu are test-only flake inputs: the
package and the module never depend on them.

## Alternatives considered

- **`prometheus/client_golang`.** A large dependency for seven families; the convention allows
  hand-written exposition and masu's validator checks it.
- **Metrics on a configured genkan listener (`/metrics` path on a route).** Mixes public and
  internal traffic; the convention requires a loopback listener.
- **Rebinding the metrics listener on SIGHUP.** More code in the swap for a value the
  deployment sets once; the restart trigger costs one restart when it changes.
- **Plain-text output for `validate`.** Friendlier in a terminal, but as `ExecReload` it would
  put non-schema lines in the unit's journal.
- **Disabling journald's rate limit.** An unbounded flood would evict other units' history.

## Consequences

- `journalctl -u genkan -o cat | jq` replaces reading free text; `journalctl` field filters do
  not see service fields.
- The TLS handshake counter depends on net/http's error text; a Go release that rewords it
  breaks `TestHandshakeErrorAndExpiry`, not production silently.
- Above 1000 request lines/s journald drops lines; sampling is not in scope.
- The milestones' "admin listener" proposal is reduced to `/healthz`.

## Status

Accepted — 2026-10-20 (planned by the owner with the observability stack).
