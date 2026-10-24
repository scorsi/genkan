# ADR 0014: Per-listener request budget and HTTP/2 stream cap (G9)

## Context

ADR 0007 caps connections at 4096 per listener and sizes descriptors at two per connection. Review
note G9: HTTP/2 multiplexes up to 250 concurrent streams per connection by default in Go, each
stream can hold its own upstream HTTP/1.1 connection (`MaxIdleConnsPerHost` limits idle ones
only), and slow continuous transfers are allowed by design. 4096 connections × 250 streams is far
above `LimitNOFILE = 65536`. v1.0 exposes the homelab's HTTP to the public through the edge, so the
bound has to hold before deployment.

## Decision

- **Requests in flight: 4096 per listener** (`serve.MaxRequests`). A slot is held from routing to
  the end of the response; a request that finds none free is answered `503` at once, logged and
  counted like any request. Nothing waits for a slot, so goroutines stay bounded by streams, not
  by a queue. The budget belongs to the bound address and survives reloads.
- **HTTP/2 concurrent streams: 100 per connection** (`serve.MaxStreams`, RFC 9113's recommended
  minimum), through `http.Server.HTTP2`.
- Descriptors per listener: 4096 client connections + at most 4096 upstream connections or open
  files + the idle pool (32 per backend) ≈ 8.3 k; two listeners on the homelab ≈ 17 k, under 65536.
  Passthrough connections count against the 4096 connections, two descriptors each.

## Alternatives considered

- **Queue requests above the budget.** Smoother for bursts, but a queue is unbounded goroutines
  and memory under abuse, the thing being bounded.
- **Only lower `MaxConcurrentStreams`.** 4096 × 100 still exceeds the descriptor limit.
- **A per-backend cap (`MaxConnsPerHost`).** Bounds upstreams but makes requests wait inside the
  transport, unbounded, and does not count static file opens.

## Consequences

- Supplements ADR 0007's connection-cap row; values are constants like the others.
- Above 4096 concurrent requests on one listener clients see 503 instead of exhausting genkan for
  every listener.
- The two values (4096, 100) stand until a measured need changes them; both are in `docs/config.md`.

## Status

Accepted — 2026-10-24.
