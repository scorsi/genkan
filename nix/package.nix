{
  lib,
  buildGoModule,
  src,
}:
buildGoModule (finalAttrs: {
  pname = "genkan";
  version = "0.2.0-dev";
  inherit src;

  # Changes whenever go.sum does: set to lib.fakeHash and read the new value from the build error.
  vendorHash = "sha256-lazNc0oICMLE52AZoFEdqMQxWgewUazg9kQP4BPUoE8=";

  ldflags = [
    "-s"
    "-w"
    "-X main.version=${finalAttrs.version}" # genkan_build_info and the start event
  ];

  # `nix flake check` runs this phase: vet first, then the default `go test ./...`.
  preCheck = ''
    go vet ./...
  '';

  meta = {
    description = "Reverse proxy for a Nix-managed homelab";
    homepage = "https://github.com/scorsi/genkan";
    license = lib.licenses.asl20;
    mainProgram = "genkan";
  };
})
