# ADR 0009: A certificate pair not ready yet does not stop genkan

## Context

ADR 0004 makes a missing or unparsable certificate file fatal at start and a failed reload
on SIGHUP. With hanko as the only issuer, two ordinary situations hit that rule:

- **First boot, or a certificate added to the config.** hanko has not issued it yet: its
  files do not exist. The module now orders genkan after `hanko.service` (a oneshot that
  stays active), but an issuance can fail or be retried later, and a sops-only host has no
  hanko at all. A fatal start makes systemd restart genkan until `StartLimitBurst` stops it,
  and hanko skips reloading a unit that is not active, so nothing brings the proxy back once
  the certificate exists. Every other site behind genkan is down meanwhile, against the
  intent of ADR 0003 ("a bad config must never take the whole homelab offline").
- **Renewal.** hanko replaces `fullchain.pem` and `key.pem` by two renames and reloads genkan
  after both. A reload arriving in between (a `nixos-rebuild switch`, a sops reload) reads
  a new certificate with the old key. ADR 0004 then rejects the whole reload, including
  unrelated changes it carried.

## Decision

A certificate pair is **not ready** when one of its files does not exist, or when its key
does not match its certificate. Not ready is not an error:

- genkan logs a `certificate-not-ready` warn line (`certificate`, `kept`, `err`) and goes on;
- at start the certificate is left out: its hosts fail the TLS handshake like an unknown
  name, every other host is served;
- on reload, the pair already loaded under that name stays in use (`kept: true`), or the
  certificate stays left out if none was loaded;
- the reload that follows hanko's write (hanko always reloads genkan after both files are in
  place) loads the pair.

Every other failure (permission denied, unparsable PEM) keeps ADR 0004's rule: fatal at
start, the whole reload rejected on SIGHUP. Those are configuration mistakes, not timing.

The NixOS module orders genkan `After=` and `Wants=` `hanko.service` when `services.hanko`
is enabled on the host, so on boot the files usually exist before genkan reads them.

## Alternatives considered

- **Keep ADR 0004's rule, rely on the ordering alone.** A failed or delayed issuance still
  takes down every site, and the renewal race still rejects unrelated reloads.
- **Retry with backoff at start.** Blocks `READY=1`; `TimeoutStartSec` then fails the unit
  the same way, and nothing is served in the meantime.
- **Treat every load error as not ready.** A garbage file or a permission mistake would be
  silent apart from a warn line; ADR 0006 relies on the permission error being loud.

## Consequences

- ADR 0004's sentence "A missing or unparsable file fails startup and fails a reload" is
  narrowed to unreadable and unparsable files.
- A name whose certificate is not ready answers `unrecognized_name`; the
  `certificate-not-ready` line and the absence of its
  `genkan_certificate_expiry_timestamp_seconds` series are the signals to alert on.
- ADR 0008's list of lifecycle events gains `certificate-not-ready`.
- Detecting a mismatch depends on crypto/tls's error text ("does not match"), which has no
  sentinel; `TestCertificateNotReady` breaks if a Go release rewords it.

## Status

Accepted — 2026-10-21
