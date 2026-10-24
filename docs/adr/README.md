# Architecture Decision Records

Short records: Context, Decision, Alternatives considered, Consequences,
Status. One decision per file, numbered, never rewritten once accepted: a
change is a new ADR that supersedes the old one.

| # | Title | Status |
|---|---|---|
| [0001](0001-single-binary.md) | One binary for the homelab proxy and the public edge | Accepted |
| [0002](0002-config-model.md) | Declarative config: explicit TOML as internal format, NixOS module as the user interface | Accepted |
| [0003](0003-reload-and-process-lifecycle.md) | Reload on SIGHUP, keep the running config on failure, readiness via sd_notify | Accepted |
| [0004](0004-certificate-source.md) | Certificates are files on disk, issued by hanko; no ACME in genkan | Accepted |
| [0005](0005-dependencies.md) | Dependency policy | Accepted |
| [0006](0006-service-identity-and-permissions.md) | Static system user, bind capability, read-only everything else | Accepted |
| [0007](0007-exposure-limits.md) | Limits on public exposure: deadlines, idle timeouts, half-close, connection caps | Accepted |
| [0008](0008-observability.md) | Observability: schema logs on stderr, loopback /metrics, journald rate limit | Accepted |
| [0009](0009-certificate-not-ready.md) | A certificate pair not ready yet does not stop genkan | Accepted |
| [0010](0010-reload-safe-session-resumption.md) | Certificate-bound session resumption across reloads | Accepted |
| [0011](0011-quiet-paths.md) | Per-route quiet paths: successful polls are counted, not logged | Accepted |
| [0012](0012-l4-passthrough.md) | L4 passthrough: dispatch before TLS, PROXY policy, rejections and their records | Accepted |
| [0013](0013-proxy-listener-exposure.md) | Sites stay off PROXY listeners unless they name them (G8) | Accepted |
| [0014](0014-request-budget.md) | Per-listener request budget and HTTP/2 stream cap (G9) | Accepted |
| [0015](0015-reload-is-signal-delivery.md) | A successful `systemctl reload` means valid and signalled, not applied (G10) | Accepted |
