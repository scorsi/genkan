# ADR 0011: Per-route quiet paths: successful polls are counted, not logged

## Context

ADR 0008 writes one `request` line per request. On ishizue, over 24 hours, 85,473 of 89,259
lines (96 %) were the Forgejo Actions runners polling for work:
`POST /api/actions/runner.v1.RunnerService/FetchTask`, status 200, 3 bytes, every ~2 s from each
of two runners (one over loopback, one over kekkai). These lines say nothing the request metrics
do not already say, and they bury the rest: browser traffic, git fetches, and the runners'
`UpdateTask` and `UpdateLog` calls (~1,800 a day) that mark when a task starts, progresses and
ends.

The runner cannot be routed around genkan: it will not stay on loopback. The homelab is small,
so a rare odd request must never be lost; sampling would lose exactly those.

## Decision

A route (`http` or `static`) may list `quiet_paths` (docs/config.md): exact request paths,
compared with the logged `path` (`URL.Path`, no query). A request to one of them whose handler
returns normally with a status below 400 writes no `request` line. Everything else about it is
unchanged:

- Metrics count it like any request (`genkan_requests_total`, duration, bytes).
- A status of 400 or more is logged: 4xx, 5xx, `502` after an `upstream-error` (whose own warn
  line stays too). So is a response aborted mid-body (ReverseProxy's `http.ErrAbortHandler`
  panic), whose recorded status is still 200.
- Other paths of the route, and the same path on other routes, are logged.

Paths are exact strings, no prefix, glob or regex: the config has no path-matching idiom yet
(`path_prefix` is a v1.2 proposal), and one exact path is the whole need. Validation: each path
starts with `/`, contains no `?` or `#`, appears once; `tcp` routes may not set it. The lookup
is a map per route, filled at build time; the hot path does one lookup only for a successful
request on a route that has quiet paths, and allocates nothing.

The NixOS module exposes it as `services.genkan.sites.<host>.quietPaths`.

This amends ADR 0008's "one per request": still one per request, except successful requests to a
route's quiet paths. No sampling, no level change, no per-client rule.

## Alternatives considered

- **Sampling.** Loses rare requests; ruled out by the owner.
- **Routing the runner straight to Forgejo.** The runner does not stay on loopback; it needs the
  same TLS front as every other client.
- **Logging quiet requests at `debug`.** Still costs the formatting, and `log.level = "debug"`
  would bring the flood back with every other debug line.
- **Matching on user agent or method.** Would also hide `UpdateTask` and `UpdateLog`, which are
  wanted; the path alone isolates the poll.
- **A global list.** Paths only mean something for one backend; per route keeps the scope narrow.

## Consequences

- On ishizue, setting the FetchTask path on the Forgejo site removes ~96 % of request lines; the
  poll stays visible as a count in `genkan_requests_total` and every failed poll is still a line.
- A successful quiet request leaves no trace in the logs, by design: who polled, from where and
  how fast is only in metrics, aggregated per route.
- If Forgejo renames the RPC, the new path is logged again until the config follows.

## Status

Accepted — 2026-10-24 (owner decision, measured on ishizue). Amends ADR 0008's request line.
