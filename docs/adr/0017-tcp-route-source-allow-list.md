# ADR 0017: Per-route source allow-list on `tcp` routes

## Context

A services listener carries several L4 SNI passthrough routes (ADR 0012): observability stores, a
backup store, later forge runners in mTLS. genkan never decrypts these flows. The overlay network
in front of the listener filters by port only, so every node that can reach the port can reach
every route on it. Overlay source addresses are bound to node keys, so the source address of a
connection on the overlay identifies a node, and a per-route list of allowed sources is a
meaningful filter. ADR 0012 has listener-level filtering only (`trusted_sources`, for PROXY
senders).

## Decision

**Key.** A `tcp` route gains `allow`, a list of CIDRs or single addresses (`"10.0.0.0/24"`,
`"fd00::/64"`, `"10.0.0.5"`; an address stands for its /32 or /128). NixOS module:
`passthrough.<name>.allow`, default `null`, written to the TOML whenever it is not `null`.

**Explicit, not implicit.** An open route is written, never inferred:

- `allow = []` is a validation error: it reads as either "nobody" or "everybody". The message
  asks for the allowed sources, or for the explicit open form.
- Every source is `allow = ["0.0.0.0/0", "::/0"]`, plain CIDRs and no keyword. One family alone
  is valid and means that family only.
- Once one `tcp` route of a listener has `allow`, every `tcp` route of that listener must have
  one; the error names the route without it. A listener with no `allow` on any route keeps the
  behaviour before this ADR (absent: no filter), so existing configurations stay valid.

**Which address.** The client address genkan already trusts for that connection: the PROXY
header's source on an `accept_proxy` listener (whose peer was checked against `trusted_sources`
first), the TCP peer otherwise. On a PROXY listener the peer is the sender, not the client, so
checking it would make the list a second `trusted_sources`. A `LOCAL` header keeps the peer
address (ADR 0012), so a sender's own health check is matched by the sender's address. IPv4
clients reported as IPv4-mapped IPv6 by a dual-stack socket are matched as IPv4.

**When.** After routing, before anything is dialed: on a `tls` listener once the SNI selected the
route, on a `tcp` listener for its single route. A refused connection is closed without a byte
forwarded and without a backend dial. The list belongs to the listener state read at accept, so
it follows reloads per connection like routes (ADR 0012); an established passthrough is not
re-checked.

**Records (ADR 0012 style).** The existing `connection-rejected` info event, without error text,
with `listener`, `route`, `client` (peer `host:port`, as the other rejections) and
`reason = "source-not-allowed"`; counted in the existing
`genkan_connections_rejected_total{listener,reason}` with that new reason value. No new metric
family, no `route` label on the counter (the log line names the route).

**Validation.** `allow` on an `http` or `static` route is an error. Each entry must parse as a
CIDR or an IP address without zone, must not be IPv4-mapped IPv6 (it would never match an
unmapped client: write the IPv4 form), and must not set bits past its prefix length
(`10.0.0.5/24` is refused as an ambiguous typo).

**`http` and `static` routes: not now.** Their boundary is the listener (ADR 0013), a refusal
there would be a per-request HTTP answer (403) rather than a closed connection, and HTTP backends
carry their own authentication. No current use case needs it; it would be its own ADR.

## Alternatives considered

- **Check the TCP peer on PROXY listeners too.** The peer is always a trusted sender there; the
  list would only duplicate `trusted_sources`.
- **Per-listener allow-list.** One listener carries routes for different clients; a listener
  list forces one port per client group, which is what the overlay already gives.
- **A new counter `genkan_connections_refused_total{listener,route}`.** The rejection family
  already exists with a closed `reason` set; one more value is the smallest change.
- **Empty list means deny all.** A route nobody may use is a route to delete; making `[]` a
  silent black hole is a trap.
- **Empty list means no filter.** The first proposal of this ADR. Rejected by the owner: `[]`
  is ambiguous, and a route that silently lets everyone in next to filtered routes on the same
  listener is the mistake the list exists to prevent.
- **A keyword such as `"any"` for the open form.** Rejected for plain CIDRs: no special value to
  parse and document, and the open form says which families it covers.

## Consequences

- A route's allow-list is only as strong as the source addresses on the network that reaches it:
  meaningful on the overlay (addresses bound to keys) and behind a trusted PROXY sender, weak on
  a network where addresses can be spoofed.
- Refused sources still complete a TCP handshake and send a ClientHello: the SNI the client asked
  for is learned before the refusal.

## Status

Accepted — 2026-10-31 (owner decision, including the checked address, the refusal of entries
with bits past the prefix, and explicit open routes).
