# ADR 0015: A successful `systemctl reload` means the config is valid and signalled, not applied (G10)

## Context

ADR 0003 says every reload-related failure is visible in `nixos-rebuild switch` output. Review
note G10: `ExecReload` runs `genkan validate` and sends SIGHUP; certificate loading and binding
happen afterwards in the running process. A pair that fails to parse or a new address already in
use fails the reload after systemd has reported success; genkan keeps the old config (correct) and
logs `reload-failed`. v1.0 adds listeners on new addresses (the PROXY listener, edge ports), so
bind failures at reload become likelier. hanko falls back from a failed reload to a restart: a
synchronous failure report would turn a safely rejected reload into a restart onto bad files.

## Decision

- Keep the signal-only reload. Structural errors (the generated TOML) still fail at build time and
  in `ExecReload`; file and bind errors are reported only by the running process.
- The record of a reload's outcome is the log: `reloaded` or `reload-failed` (error level), plus
  `genkan_certificate_expiry_timestamp_seconds`, which only moves when new certificates are
  actually served. Deployment checks and alerting watch those, not the exit status of
  `systemctl reload`.
- ADR 0003's sentence "Every reload-related failure is visible in `nixos-rebuild switch` output" is
  narrowed accordingly; the rest of ADR 0003 stands.

## Alternatives considered

- **Synchronous reload (ExecReload waits for an acknowledgement over the notify socket or a
  pidfile).** Truthful exit status, but hanko's reload-then-restart fallback would restart genkan
  onto the files it just rejected; it needs a coordinated change in hanko first.
- **Restart instead of reload.** Drops every connection on each certificate renewal.

## Consequences

- No code change. The VM tests keep asserting `reload-failed` in the journal after a reload that
  systemd reports successful.
- A synchronous acknowledgement, together with a hanko change that stops restarting on a rejected
  reload, is reconsidered only if alerts on `reload-failed` and on certificate expiry (with the
  observability work) prove insufficient.

## Status

Accepted — 2026-10-24. Narrows ADR 0003.
