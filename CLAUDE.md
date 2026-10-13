# genkan

Reverse proxy in Go for a Nix homelab. Read `docs/adr/README.md` and
`docs/milestones.md` before proposing anything.

## Working rules

- Discussion happens in French; everything committed to the repo is in
  English.
- Design phase: the user writes the core code. Claude produces ADRs, docs,
  and later tests, boilerplate and refactoring when asked. No implementation
  code unless the user asks for it.
- Every structural decision gets an ADR (`docs/adr/NNNN-kebab-title.md`,
  sections: Context, Decision, Alternatives considered, Consequences, Status)
  and a row in `docs/adr/README.md`. Accepted ADRs are not rewritten; a new
  ADR supersedes them.
- Nothing enters the scope without the user's agreement. Present options with
  trade-offs and a recommendation; the user decides.
- Questions that belong to kekkai (overlay network) or Torii (public VPS, a
  sekkeizu host) are flagged, not decided here.

## Hard constraints

- No Tailscale integration. Tailscale is a transitional provider of an
  overlay address and of certificate files only.
- Secrets in config are sops file paths, never values.
- Dependencies: only those listed in ADR 0005; anything else needs an ADR.
- Nix flake is mandatory: package (`buildGoModule`), NixOS module, devShell,
  checks. Unit tests run under `nix flake check`; the NixOS VM test runs on
  Forgejo CI (Linux only).

## Vocabulary

- sekkeizu: the homelab Nix repo. Hosts: `jiban` (nix-darwin), `ishizue`
  (NixOS VM, runs genkan), Torii (future public VPS, runs genkan in
  passthrough role), later mini-PCs and a NAS.
- kekkai: the future overlay network replacing Tailscale; provides stable
  per-node addresses and transport encryption.
- kajiba: a future git forge; may need path-prefix routing.
- Go packages take plain English names (`config`, `router`, `cert`, `serve`);
  Japanese names are for repos and hosts only.
