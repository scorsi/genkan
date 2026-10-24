# ADR 0012: L4 passthrough: dispatch before TLS, PROXY policy, rejections and their records

## Context

Milestone v1.0 implements what ADR 0002 sketched: a `tls` listener peeks the SNI and forwards a
`tcp` route's stream raw, a `tcp` listener forwards the whole port, `accept_proxy` and
`send_proxy` carry the client address over the overlay, under ADR 0007's L4 limits. ADR 0002,
ADR 0007 and ADR 0008 leave the following open: how the peek is done, what happens to bytes that
are not a ClientHello, which PROXY headers count as valid, what an established passthrough does on
reload, and how L4 connections are logged and counted. ADR 0005 allows `go-proxyproto`.

## Decision

**Dispatch.** Every listener accepts through one goroutine per connection, before the
`http.Server`, which now serves an in-memory listener fed with the connections whose TLS genkan
terminates. The listener's state is read once, at accept: routes, mode and PROXY policy follow
reloads per connection, as requests already do.

**Peek.** The ClientHello is read by `crypto/tls` itself (a server handshake on a read-only view
that stops in `GetConfigForClient`): records fragmented across reads or across several TLS records
are reassembled by the standard library, the size is bounded by its 64 KiB handshake limit, and
every byte read is replayed to whoever gets the connection next. No hand-written parser.

- SNI of a `tcp` route on the listener: forwarded raw, peeked bytes first.
- Otherwise, on a listener with `http` or `static` routes: handed to the TLS server, which answers
  as in v0 (unknown or absent SNI fails with `unrecognized_name`). Bytes that are not a
  ClientHello go there too, so v0's `tls-handshake-error` lines and net/http's 400 to plaintext
  HTTP are unchanged.
- Otherwise (only `tcp` routes): closed, no alert. A peek that times out is closed everywhere.

**PROXY policy (`accept_proxy = "required"`).** The TCP peer is checked against
`trusted_sources` before anything is read; then the connection must start with a v2 header
(`go-proxyproto`'s `Read`). A v1 header, no header or a malformed one closes the connection.
A `PROXY` command replaces the connection's remote and local addresses with the header's, so access
logs, `X-Forwarded-For` and an onward `send_proxy` carry the client. A `LOCAL` command (a sender's
own health check) keeps the peer address. TLVs are ignored. One deadline covers accept to complete
header and ClientHello: 5 s (ADR 0007).

**`send_proxy = "v2"`.** The backend connection starts with a v2 header built from those two
addresses; a mixed IPv4/IPv6 pair is sent as IPv6 with a mapped address (library behaviour).

**Copying.** One idle deadline shared by both directions (ADR 0007's "1 h without a byte in either
direction"): a direction waiting on a silent peer is re-armed while the other one moves. EOF on
one side half-closes the other side's write, both ways; any other error closes both. The backend
dial uses the HTTP dial timeout (5 s).

**Reload and stop.** An established passthrough keeps the backend it was opened to; a reload that
changes the route affects new connections only. A listener removed by a reload, and a stopping
genkan, close its passthrough connections at once: no draining, as for HTTP (ADR 0003).

**Validation.** A `tcp` route may not mix `tls` and `tcp` listeners: on the `tls` one it would
have no `sni` (forbidden by the `tcp` one) and be unreachable. `sni` names follow the host rules
(lowercase, no port, no wildcard before v1.2).

**Records (ADR 0008 style).**

- `connection` (info, when `log.access`): one per finished passthrough, with `listener`, `route`,
  `client` (address only), `sni` (`-` on a `tcp` listener), `bytes_in` (client to backend),
  `bytes_out`, `dur_us`.
- `connection-rejected` (info): `listener`, `client` (peer `host:port`), `reason`; no error text. Reasons,
  a closed set: `untrusted-peer`, `proxy-header`, `client-hello` (timeout, or not a ClientHello on
  a listener that does not terminate TLS), `unknown-sni`.
- `upstream-error` (warn) on a failed backend dial or PROXY header write, as for HTTP.
- `accept-error` (warn): `Accept` failed for another reason than a closed listener (EMFILE);
  retried after 100 ms, as net/http does.
- Metrics: `genkan_connections_total{listener,route}`,
  `genkan_connection_bytes_total{listener,route,direction="in|out"}`,
  `genkan_connections_rejected_total{listener,reason}`; `genkan_upstream_errors_total{route}`
  also counts failed L4 dials. Labels are configured names and closed sets (masu convention).

## Alternatives considered

- **A hand-written ClientHello parser.** ~100 lines plus fragmentation handling to test; the
  standard library already does it and stays maintained.
- **`go-proxyproto`'s `Listener` with a policy function.** Its policy decides per connection
  inside `Accept`/first read, and its timeout and error paths are its own; checking the peer
  first and calling `Read` on a buffered reader keeps the order of ADR 0002 ("rejected before any
  byte is read") explicit and the deadline shared with the peek.
- **Closing non-ClientHello bytes on every listener.** Simpler, but changes v0's behaviour and
  its handshake-error counter on the LAN listener for no gain.
- **`connection-rejected` at warn with the error text.** A rejection on the PROXY listener
  (untrusted peer) is a security signal, but a public edge is scanned all day: warn lines would
  drown real warnings. The closed `reason` set and `genkan_connections_rejected_total` carry the
  signal; an alert watches the counter (owner, 2026-10-24).
- **Dropping established passthroughs on any reload.** Would cut SSH sessions on every config
  change; only a removed listener does.

## Consequences

- One more goroutine and one in-memory hop per accepted connection, including terminated ones.
- A listener's `MaxConns` cap (ADR 0007) counts passthrough connections like the others; the
  backend side of a passthrough is the second descriptor of ADR 0007's calculation.

## Status

Accepted — 2026-10-24 (owner: info, without the error text).
