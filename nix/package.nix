{
  lib,
  buildGoModule,
  src,
}:
buildGoModule {
  pname = "genkan";
  version = "0.1.0-dev";
  inherit src;

  # No external module yet: set to a real hash once go.sum exists (ADR 0005).
  vendorHash = null;

  ldflags = [
    "-s"
    "-w"
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
}
