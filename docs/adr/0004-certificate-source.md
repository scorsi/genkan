# ADR 0004: Certificates are files on disk, issued by hanko; no ACME in genkan

## Context

Private keys never leave the homelab (the edge is SNI passthrough, ADR 0001).
Certificates come from several places over time:

- Development: self-signed certificates in tests. genkan is not deployed
  before real certificates exist; there is no transitional source.
- For every name, internal and public: Let's Encrypt via DNS-01, issued by
  **hanko**, the certificate service of the homelab. hanko writes the
  challenge records through RFC 2136 to annai, the public nameserver (annai
  ADR-0006, ADR-0009). It writes `fullchain.pem` and `key.pem` under its state directory and reloads
  genkan (ADR 0003). A wildcard covers the internal names; public names
  reached through the edge get their own certificates the same way, since annai's
  public zone accepts `_acme-challenge.*` for any name under the apex.
- Later, maybe: a private CA for mTLS between services. That is a possible
  second issuer inside hanko and is not decided here; for genkan it would be
  more files, and at most a client-certificate verification option.

The ownership split is: annai owns DNS, kekkai owns the overlay, genkan only
proxies, hanko owns certificates. No product shares code with another.

## Decision

- Every `[certificates.<name>]` entry is a `cert` and `key` pair of paths
  (ADR 0002). genkan loads every pair at start and on SIGHUP, builds the
  SNI-to-certificate map from the routes, and swaps it atomically. A missing
  or unparsable file fails startup and fails a reload (previous map kept). At
  load, SANs not covering the route's hosts log a warning.
- The handshake only carries the SNI, not a certificate name. The
  SNI-to-name resolution of ADR 0002 therefore happens when a config is
  loaded: the `http`/`static` routes and the `[certificates]` table are joined
  into one SNI-to-certificate map, and `tls.Config.GetCertificate` is a lookup
  of `hello.ServerName` in that map. The router is not involved at handshake
  time.
- **genkan runs no ACME challenge**: no TLS-ALPN-01, no HTTP-01, no DNS-01,
  no account key, no writable state. There is a single certificate source, so
  the code holds a plain map and a `tls.Config` closure; no source interface.
- No DNS provider, no CA code in genkan.

## Alternatives considered

- **ACME TLS-ALPN-01 inside genkan** (`autocert`). Rejected: it ties issuance
  to the proxy and to the edge's SNI list, needs a writable state directory and
  an account key owned by the proxy, and DNS-01 through hanko already covers
  public names.
- **HTTP-01.** Needs the edge to forward port 80 and genkan to answer on it.
  Rejected; the port 80 listener exists later only for redirects.
- **DNS-01 inside genkan.** Needs a DNS client and a TSIG secret inside the
  proxy. Rejected.
- **NixOS `security.acme` (lego).** Works, but its RFC 2136 provider updates
  a single nameserver and checks propagation through the system resolver,
  which annai's split horizon defeats (annai ADR-0004). hanko exists to do
  both correctly and to host a private CA later.
- **Automatic selection by SAN across all loaded certificates**, as
  `crypto/tls` does natively. Rejected for the explicit per-route link, see
  ADR 0002.
- **Watching certificate files for changes.** sops-nix and hanko both trigger
  a reload of named units. Rejected (ADR 0003).

## Consequences

- genkan has no dependency on any ACME library (ADR 0005) and no writable
  path (ADR 0006).
- genkan reads hanko's files through the `hanko` group; the paths are a Nix
  contract between the two modules, in the deployment repository.

## Status

Accepted, 2026-10-12.
