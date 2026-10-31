# ADR 0016: HTTP/2 cleartext (h2c) to backends, per-route; per-stream progress bound

## Context

The forge backend serves one plaintext port that accepts HTTP/1.1 and HTTP/2 with prior knowledge
(h2c): native gRPC and grpc-web, git smart HTTP, and its UI. Clients reach it through genkan over
TLS. gRPC needs HTTP/2 end to end: the call's status (`grpc-status`, `grpc-message`,
`grpc-status-details-bin`) travels only in trailers, and a bidirectional stream needs both
directions open at once. Until now genkan spoke HTTP/1.1 to every backend, and the milestones
listed "`h2c` to backends" as not planned.

The calls are long-lived: a runner holds a bidirectional stream for hours with a heartbeat every
10 s, server streams can stay silent for more than a minute, and client-streaming uploads reach
64 MiB. ADR 0007 bounds a request body and a response at 60 s without a byte, a constant, and
measures backend silence on the upstream TCP connection. Over h2c many streams share one
connection: a per-connection deadline would let one busy stream keep a silent sibling alive and,
when it fires, kill every stream on the connection.

## Decision

**Per-route `h2c`.** An `http` route gains `h2c` (bool, default false; module: `sites.<host>.h2c`).
On such a route, a request that reached genkan over HTTP/2 goes to the backend over HTTP/2
cleartext with prior knowledge, no `Upgrade: h2c`. A request that reached genkan over HTTP/1.1
(git clients that negotiate it, WebSocket and other `Upgrade` requests) stays HTTP/1.1. The
backend must accept both on its port. Standard library only (ADR 0005): a second
`http.Transport` whose `Protocols` holds only `UnencryptedHTTP2`.

**Per-route `progress_timeout`.** An `http` route gains `progress_timeout` (a Go duration, module:
`sites.<host>.progressTimeout`), replacing ADR 0007's 60 s on that route's request bodies and
responses, for HTTP/1.1 and HTTP/2 alike. Absent, the 60 s stands. This is the key ADR 0007's
alternatives anticipated "when a backend proves the constant wrong". There is still no absolute
response deadline on any route.

**The bound on an h2c stream is per stream.** The wait for the backend's response headers stays
unbounded (ADR 0007). Once they are in, one timer per stream cancels that stream, and only it, when
no byte has moved in either direction (client body read, backend body read) for the route's
timeout. A heartbeat in one direction therefore keeps a bidirectional stream alive, a silent
stream is not kept alive by a sibling, and cancelling it resets one stream, not the connection.
Before the headers, the client body keeps ADR 0007's per-read deadline with the route's timeout.
Writes to the client keep the per-write deadline (a client that stops reading a stream is cut
after the route's timeout). On the h2c connection itself, `HTTP2Config.WriteByteTimeout = 60 s`
closes a socket that takes no byte while data is waiting: flow control keeps a slow stream from
blocking the socket, so this only catches a frozen backend.

**Unchanged and now tested.** The TLS listener offers ALPN `h2` then `http/1.1`. Trailers are
relayed (ReverseProxy announces or prefixes them; the router's response writer passes `Header`,
flushes through `http.ResponseController` and `Unwrap`). `te: trailers`, `content-type`, `Origin`
and `Host`/`:authority` pass unchanged (the inbound `Host` is kept, ADR 0002). Responses without a
length are flushed per write. No request size cap: a 64 MiB client stream passes. HTTP/2 streams
stay capped at 100 per client connection (ADR 0014); upstream h2c streams are bounded by the
request budget like upstream HTTP/1.1 connections were.

## Alternatives considered

- **Every request of an h2c route over h2c.** HTTP/2 has no `Upgrade`, so WebSocket and other
  upgrades would break, and an HTTP/1.1 client gains nothing from it.
- **`Upgrade: h2c` instead of prior knowledge.** Deprecated by RFC 9113, needs a request body
  replay, and the backend already accepts prior knowledge.
- **`golang.org/x/net/http2`.** A dependency for what `net/http` ships since Go 1.24.
- **Keep the per-connection deadlines on h2c connections.** Siblings keep a silent stream alive,
  and a fired deadline kills them all.
- **Per-direction timers on h2c streams (ADR 0007's rule, per stream).** A runner whose heartbeat
  flows one way would be cut on the other, silent direction.
- **Raise the global 60 s.** Weakens every public route for one backend's need.

## Consequences

- Supplements ADR 0002 (two additive route keys) and ADR 0007 (one value becomes per-route; the
  h2c stream rule above). ADR 0005 is unchanged.
- A cut h2c stream is visible in its `request` line (the status was already sent) and as a reset on
  the client; no extra log event is written for it.
- A backend that stops reading an upload before sending its response headers holds that stream
  until the client or the backend gives up: flow control stops the transport from reading the
  client body, so no deadline is running. Acceptable for a local backend; after the headers the
  per-stream timer covers the same case.
- `checks.<linux>.vm` runs a 65 s silent bidirectional stream with trailers through the TLS
  listener; Go tests cover the timeouts with shortened values.

## Status

Proposed — 2026-10-31.
