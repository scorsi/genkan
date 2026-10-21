# ADR 0010: Certificate-bound session resumption across reloads

## Context

The G4 fix (3e59a9e) gives each reload state new ticket keys. This prevents
TLS 1.3 resumption from bypassing the current certificate map, but also
invalidates sessions for names whose certificates did not change.

`go.mod` requires Go 1.26 and the flake uses `pkgs.go`; the available
Nix-installed toolchain is Go 1.26.7. Its
`crypto/tls` exposes `WrapSession`, `UnwrapSession`, `SessionState.Extra`,
`EncryptTicket` and `DecryptTicket`. These allow authenticated application
metadata without implementing ticket encryption or key rotation.

## Decision

- Keep one ticket-owning `tls.Config` per bound listener address across
  successful reloads. Use its `EncryptTicket` and `DecryptTicket` methods,
  retaining Go's automatic daily rotation and seven-day key retention.
  No explicit ticket key, timer, persistence or dependency is added.
- Keep `GetConfigForClient` on every handshake. It selects an immutable
  reload state; unknown, absent and certificate-not-ready names still select
  the configuration with tickets disabled and no certificate.
- Append a versioned binding to `SessionState.Extra`: lowercased SNI and
  SHA-256 of the leaf certificate's DER. Authenticate/decrypt first, then
  require an exact binding match against the selected state's certificate
  map before allowing either TLS 1.2 or TLS 1.3 resumption. Missing metadata,
  malformed tickets and mismatches return `(nil, nil)` for a full handshake.
  A removed name fails that handshake with `unrecognized_name`.
- Keep `h2` and `http/1.1` in the selected configuration's ALPN list. Go
  negotiates ALPN on each handshake and retains its normal session version,
  cipher, lifetime and binder checks. No early data or custom TLS policy.

## Alternatives considered

- **Invalidate every session at reload.** Safe and simpler, but discards
  sessions even when only routes or unrelated certificates change.
- **Keep keys without binding tickets.** Reintroduces G4 for certificate
  changes: resumed handshakes skip `GetCertificate`.
- **Implement a key rotation scheduler or a server-side session cache.**
  Duplicates stdlib guarantees or adds per-client state for no benefit.

## Consequences

- Re-reading identical certificate files preserves resumption; a hanko renewal
  changes the leaf certificate and still requires a full handshake for that
  name. Changes to intermediate certificates alone do not invalidate sessions.
  A temporarily mismatched pair retained by ADR 0009 preserves its binding.
- A handshake uses the state selected at ClientHello, even if a reload occurs
  before it finishes, as with ordinary full handshakes. Routing still follows
  ADR 0003. Failed reloads leave the serving state untouched.
- Ticket keys remain memory-only and isolated by bound address. Restarting or
  removing and re-adding a listener invalidates its tickets. Memory is bounded
  by Go's retained key set per listener and one small binding per configured
  host; there is no per-client server cache.
- Key compromise exposes ticket session secrets for retained keys. In TLS 1.2
  this can compromise recorded sessions; TLS 1.3's fresh (EC)DHE protects past
  application traffic, but ticket secrets still enable resumption impersonation.
  Reload is no longer a ticket-key revocation mechanism; restart to discard
  keys. Go's normal ticket lifetimes and rotation bound this exposure.
- ADR 0004's file-only certificate source, ADR 0005's dependencies, ADR 0007's
  deadlines and TLS policy, and ADR 0008's logs/metrics remain unchanged.
- Tests cover TLS 1.2/1.3 with HTTP/1.1 and HTTP/2 across unchanged reloads,
  unrelated certificate changes, name removal and leaf replacement; additional
  ticket tests cover name binding, invalid metadata and rotation.

## Status

Proposed — 2026-10-21; implemented for owner review under the conditional
implementation request. Supplements ADR 0003's reload behaviour.
