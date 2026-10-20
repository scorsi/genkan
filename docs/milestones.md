# Milestones

Technical milestones, no time estimates. v0 and v1 are horizons; each
sub-milestone ships something testable with verifiable acceptance criteria.
Everything runs under `nix flake check` unless marked CI (NixOS VM test on
Forgejo CI, needs KVM or falls back to slow emulation). A breakage seen on
the real hosts becomes a VM test case before it is fixed.

## v0: homelab only

### v0.1 Core proxy

Deliverable: `genkan` serves HTTP backends by hostname over TLS from files,
with structured access logs. No reload: restart to apply config.

- Flake: package (`buildGoModule`), devShell, `checks` running `go test` and
  `go vet`.
- `genkan validate <file>` exits non-zero with a precise message on: unknown
  key, duplicate listener/route/certificate name, duplicate host on one
  listener, route referencing an unknown listener or certificate,
  `tcp` route / `accept_proxy` / `send_proxy` present ("not implemented
  before v1").
- `genkan run <file>` binds every `tls` listener, fails fast on bind or
  certificate load error.
- `http` routes: hostname match, `httputil.ReverseProxy`, `X-Forwarded-For`,
  `X-Forwarded-Proto`, `X-Forwarded-Host` overwritten (never appended to) with
  trusted values. Unknown `Host` returns 404 (TLS already failed for unknown
  SNI).
- TLS: certificate chosen by SNI via the route's `certificate`. No SNI or
  unknown SNI fails the handshake. HTTP/2 and WebSocket work through stdlib
  defaults but are not tested in this milestone. No real certificate exists
  before hanko, so v0.1 is not deployed. Multi-host behaviour is tested with
  self-signed certificates.
- HTTP limits of ADR 0007: `ReadHeaderTimeout`, `IdleTimeout`, backend dial
  timeout, per-listener connection cap.
- Access log: one slog JSON record per request (time, listener, route,
  client IP, method, host, path, status, bytes, duration, user agent).
- `docs/config.md` describes every key (written during design, kept in sync).

Acceptance: unit tests cover validation errors, host routing, header
overwriting, preservation of the inbound `Host` on the backend request
(`ProxyRequest.SetURL` rewrites it; the rewrite must restore it),
SNI-to-certificate selection, and the connection cap and header deadline,
using `httptest` and in-memory certificates. Manual: two hosts on one port proxied to two local backends.

### v0.2 Reload and NixOS module

Prerequisite: annai resolves the internal names (annai M1) and is the public
nameserver (annai M4), and hanko issues the `*.uchi.<domain>` wildcard on the
homelab host. Without those there is nothing to route.

Deliverable: deployed on the homelab host, replacing its previous reverse
proxy: the forge and the site move behind genkan on `:443` with one hostname
each. The site's current server becomes a plain HTTP backend until
v0.3 serves it as static files.

- SIGHUP: re-validate, reload certificates, rebind changed listeners, swap
  atomically; on failure keep the running config and log `ERROR`.
- sd_notify `READY=1` after all listeners are bound.
- NixOS module as shaped in ADR 0002: `listeners`, `certificates` (hosts and
  file paths), `sites`, `settings` escape hatch. Generated
  TOML validated in a derivation at build time. Unit: `Type=notify`,
  `ExecReload = genkan validate … && kill -HUP $MAINPID`, static `genkan`
  user with `CAP_NET_BIND_SERVICE` and the hardening set of ADR 0006.
- Flake exposes `nixosModules.default`.

Acceptance: unit tests for the swap (routes added/removed between two
configs, failed reload leaves old config serving). Module evaluates with
`nix eval` for a sample config; a config with a typo fails `nixos-rebuild
build`. Manual on the homelab host: `systemctl reload genkan` after a cert rotation
serves the new cert without dropping the listener.

### v0.3 Static files and VM test

Deliverable: `static` routes; a NixOS VM test in CI.

- `static` route: `http.FileServer` on `root`, directory listing disabled,
  `index.html` served for directories, 404 otherwise, no SPA fallback.
- `nixosTest`: VM with genkan, one HTTP backend, one static root, two
  hostnames, self-signed certificates; curl asserts routing, headers and
  reload behaviour. Runs on Forgejo CI (`x86_64-linux`), not in
  `nix flake check` on darwin.

Acceptance: VM test green in CI. The site served as static files by genkan on
the homelab host, its previous server retired.

## v1: Edge

### v1.0 L4 passthrough and PROXY protocol

Deliverable: genkan on the edge forwards public HTTPS by SNI and SSH by port to
the homelab over kekkai; the homelab instance accepts PROXY protocol on a
dedicated overlay listener.

- `tls` listener peeks SNI; a matching `tcp` route forwards the raw stream
  (including the peeked bytes); otherwise TLS terminates as in v0. Unknown
  SNI on a listener with only `tcp` routes closes the connection.
- `tcp` listener: whole port to one `tcp` route.
- `send_proxy = "v2"` on `tcp` routes.
- `accept_proxy = "required"` with `trusted_sources` using `go-proxyproto`:
  missing header or untrusted peer is rejected. Client IP from the header
  feeds access logs and `X-Forwarded-For`.
- L4 limits of ADR 0007: SNI peek and PROXY header deadline, idle timeout,
  half-close propagation.
- git SSH is forwarded on its own public port without `send_proxy`
  (ADR 0002): the backend's single SSH listener cannot accept the header from
  the edge and plain connections from the LAN at once.
- NixOS module: `passthrough` routes, `acceptProxy`, `trustedSources`.

Acceptance: unit tests for SNI peek (including fragmented ClientHello),
PROXY header policy (trusted, untrusted, absent), raw byte forwarding. VM
test with two genkan instances (edge role and homelab role) and a client:
the backend sees the client's address. Deployed on the edge.

### v1.1 HTTP redirect

Deliverable: port 80 redirects. Public certificates come from hanko like every
other certificate (ADR 0004); nothing to do in genkan.

- `http` listener mode: plaintext, every request answered with 301 to
  `https://` same host and path, nothing forwarded. The edge runs its own `http`
  listener on `:80`; port 80 never crosses the overlay.
- NixOS module: redirect listener toggle.

Acceptance: redirect tested in `httptest`.

### v1.2 Routing extensions

Deliverable: as needed by the growing homelab.

- Wildcards in `hosts` (`*.example.org`), exact match wins over wildcard.
- `path_prefix` on `http` routes, longest prefix wins, optional strip.
- Explicit WebSocket and HTTP/2 tests.

Acceptance: unit tests for precedence rules.

## Proposals not in scope (need agreement before entering a milestone)

- Admin listener with `/healthz` (v1+). `/metrics` on loopback is decided by
  ADR 0008.
- Connection draining on reload (when a removed listener drops something that
  matters).
- Response compression, caching, rate limiting, front auth: none requested;
  each would be its own ADR.
- `h2c` to backends, HTTP/3: not planned.
