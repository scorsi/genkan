# ADR 0006: Static system user, bind capability, read-only everything else

## Context

genkan binds privileged ports (443, and 80 on the edge), reads private keys written by
sops-nix at activation and by hanko on renewal, reloads them on
SIGHUP without a restart (ADR 0003), and serves static roots owned by other
services. It writes nothing. It runs on hosts with exactly one tenant, but
one of them is public.

## Decision

- **Identity:** a static system user and group `genkan`, declared by the
  NixOS module. No `DynamicUser`.
- **Ports:** `AmbientCapabilities = CAP_NET_BIND_SERVICE` and
  `CapabilityBoundingSet = CAP_NET_BIND_SERVICE`. Nothing else is privileged.
- **Secrets:** read in place, as the `genkan` user. sops secrets are declared
  with `owner = "genkan"`, mode `0400`, in the deployment repository. hanko's certificates are
  readable by genkan's own group (hanko's per-certificate `group`, set to
  `genkan`); no supplementary group. No `LoadCredential`.
- **Filesystem:** `ProtectSystem = "strict"`, `ProtectHome = true`,
  `PrivateTmp`, `PrivateDevices`, `NoNewPrivileges`. No writable path: genkan
  has no state. Static roots must be world-readable or group-readable by
  `genkan`; the module documents this, it does not chown.
- **Sockets:** `RestrictAddressFamilies = AF_INET AF_INET6 AF_UNIX`
  (`AF_UNIX` for `NOTIFY_SOCKET` and journald). `LimitNOFILE = 65536` to
  back the connection caps of ADR 0007.

## Alternatives considered

- **`DynamicUser = true`.** The uid is allocated when the unit starts, but
  sops-nix sets secret ownership at activation, before any unit runs, and
  needs a user that exists then. Rejected.
- **`LoadCredential` for keys.** Credentials are copied once at start;
  a SIGHUP after a certificate rotation would reload the stale copy. Rejected
  (ADR 0003 relies on re-reading the path).
- **Run as root and drop privileges after bind.** More code than one
  capability and a worse failure mode.
- **Socket activation.** Would remove the capability but ties the listener
  set to the unit file, while ADR 0002 keeps listeners in the config and
  ADR 0003 rebinds them on reload. Rejected.

## Consequences

- Every host running genkan declares its secrets with
  `owner = "genkan"`; a secret with the wrong owner fails at start with a
  permission error, which is the intended signal.
- Adding a writable path later (logs to file, cache) is a module change and a
  new ADR, not a chmod.
- The hardening set is identical on the edge and in the homelab.

## Status

Accepted, 2026-10-13.
