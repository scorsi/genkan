# ADR 0013: Sites stay off PROXY listeners unless they name them (G8)

## Context

genkan routes HTTP by `Host` per listener; SNI only selects the certificate (ADR 0002). A client
that completes a handshake for one name may send `Host` for any other name served on the same
listener, which also makes HTTP/2 connection coalescing under a wildcard certificate work. Review
note G8: in the v1.0 topology the edge forwards only public SNIs, but the homelab's PROXY listener
would serve every site bound to it, and the NixOS module bound every site without `listeners` to
every listener. A public SNI then reaches internal-only sites with a crafted `Host`.

## Decision

- In the NixOS module, a site without `listeners` is bound to every `tls` listener that does not
  set `acceptProxy`. A site meant to be public lists the PROXY listener explicitly
  (`listeners = [ "lan" "edge" ]`). The generated TOML stays explicit; genkan itself is unchanged:
  `Host` routing per listener is the boundary.
- `tcp` listeners never receive sites by default either (they cannot serve them).
- Tested: Go (`TestAcceptProxy`: public SNI with an internal `Host` on the PROXY listener is
  404), module eval (`checks.<sys>.module-unit`), and VM (`checks.<linux>.vm-edge`).

## Alternatives considered

- **Require `Host` to equal the SNI (421 Misdirected Request otherwise).** Closes the gap in
  genkan itself, but breaks HTTP/2 coalescing for browsers on a wildcard certificate unless the
  rule becomes "same certificate", which is what the per-listener binding already gives.
- **Keep the old default and document it.** One forgotten `listeners` on a new internal site
  exposes it publicly; the safe default costs one list on public sites.

## Consequences

- Before v1.0 no listener accepted PROXY headers, so no existing config changes meaning.
- A public site that forgets the PROXY listener answers 404 through the edge: a visible failure
  instead of a silent exposure.

## Status

Accepted — 2026-10-24.
