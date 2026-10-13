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
