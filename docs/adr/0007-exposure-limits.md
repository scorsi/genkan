# ADR 0007: Limits on public exposure: deadlines, idle timeouts, half-close, connection caps

## Context

The edge's listeners face the Internet. The homelab instance faces the edge's
traffic on a dedicated listener and the LAN on another. Every unbounded wait
is a way to pin a goroutine, a file descriptor and a backend connection for
free. At the same time the traffic is long-lived by nature: git pushes, large
downloads, SSH sessions, WebSockets. A wrong timeout is a bug a user hits
daily; a missing one is a bug an attacker hits once.

None of these values are configurable (ADR 0002, `docs/config.md`); they are
constants in code until a real backend needs otherwise.

## Decision

| What | Value | Why |
|---|---|---|
| SNI peek on `tls` listeners (v1.0) and PROXY header read on `accept_proxy` listeners | 5 s from accept to a complete ClientHello or header | A ClientHello is the first thing a client sends and fits in one flight; 5 s tolerates a bad mobile link. Same figure as HAProxy's conventional `tcp-request inspect-delay`. Without it a connection that sends nothing holds a slot forever. |
| TLS handshake and request headers | `http.Server.ReadHeaderTimeout = 10 s` | Go applies it to the handshake too. Bounds slowloris-style header trickling. Nginx's 60 s default is sized for the public web; a homelab with two kinds of clients needs less. |
| Request body and response, in flight | 60 s without a byte, idle not absolute. `http.Server.ReadTimeout` and `WriteTimeout` stay unset. | Go's server timeouts are absolute and would cut a slow but continuous git push or a long download. Instead genkan pushes the deadline on every progress: a reader wrapping the request body calls `http.ResponseController.SetReadDeadline` on each `Read`, a writer wrapping the response calls `SetWriteDeadline` on each `Write`. A body trickled byte by byte or a response the client never reads is cut after 60 s of silence; continuous traffic at any speed passes. Hijacked connections (WebSocket) leave these deadlines behind and get the L4 idle rule when WebSocket enters scope (v1.2). |
| HTTP keep-alive between requests | `IdleTimeout = 120 s` | Browsers reuse connections for a few minutes; a dead idle slot is cheap but not free. |
| Request headers size | Go default (1 MiB) | No backend needs more; no reason to change a default. |
| Backend connect | dial timeout 5 s, no `ResponseHeaderTimeout` | A backend on the same host that does not accept within 5 s is down; returning 502 fast beats queuing. Headers can legitimately take long (git pack processing), so no header timeout. Transport `MaxIdleConnsPerHost = 32`, `IdleConnTimeout = 90 s`. |
| L4 passthrough idle (v1.0) | 1 h without a byte in either direction | Dead peers are TCP keepalive's job: Go probes every 15 s by default and Linux gives up after 9 probes, about 2 min. The idle timeout only reclaims connections where both ends are alive and silent, which for SSH and WebSockets is legitimate use, so it is long. TLS passthrough is in practice bounded by the homelab instance's HTTP timeouts, which close the stream and propagate. |
| L4 half-close (v1.0) | propagated | When one side closes its write direction, genkan calls `CloseWrite` on the other and keeps copying the remaining direction until it ends or idles out. Needed for protocols that signal end-of-request with a half-close. |
| Concurrent connections | 4096 per listener | Above the cap genkan stops calling `Accept` until a slot frees (a semaphore around `Accept`, written locally since `x/net/netutil` is not an allowed dependency). The kernel backlog absorbs bursts and excess SYNs are dropped; clients retry. Per listener, so public abuse on the `edge` listener cannot starve `lan`. Worst case fds: 2 listeners × 4096 × 2 ends = 16384, under `LimitNOFILE = 65536` (ADR 0006). |
| TLS | minimum 1.2, Go's default suites and curves, no renegotiation, no client auth | Go's defaults are maintained; genkan adds nothing. |

## Alternatives considered

- **Config keys for each value.** No consumer exists and each key is a
  decision pushed onto the Nix side. A key gets added when a backend proves
  the constant wrong (ADR 0002 consequence).
- **`ReadTimeout` and `WriteTimeout` on the server.** Rejected: absolute, so
  either too short for a legitimate transfer or too long to bound an attacker.
  The per-progress deadline is the idle-based variant Go does not ship.
- **Accept-and-close above the cap.** Costs work per attacker connection and
  fails clients immediately, while stopping `Accept` is free and lets
  retries succeed.
- **A short L4 idle timeout (minutes).** Would kill idle SSH sessions and
  idle WebSockets through passthrough; dead peers are already handled by TCP
  keepalive.
- **A global cap instead of per listener.** Lets public traffic starve the
  LAN listener.

## Consequences

- The attack surface genkan accepts: an attacker can hold up to 4096 slots on
  a public listener for up to the applicable timeout. Everything else keeps
  running. Rate limiting and connection limits per source are proposals, not
  scope.
- HTTP values apply from v0.1; the L4 rows from v1.0; PROXY header deadline
  from v1.0.
- Each value has one named constant and one unit test that exercises the
  timeout path (a connection that sends nothing is closed at the deadline, a
  body that stalls for 60 s is cut while a slow continuous one completes, a
  half-closed stream finishes the other direction).

## Status

Accepted, 2026-10-13.
