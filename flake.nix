{
  description = "genkan (玄関, the entrance) — reverse proxy for a Nix-managed homelab: package, NixOS module, dev shell";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";

  outputs =
    { self, nixpkgs, ... }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      pkgsFor = system: nixpkgs.legacyPackages.${system};

      # Only what the Go build reads: editing the docs or the Nix files doesn't rebuild the binary.
      src = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          ./go.mod
          (lib.fileset.maybeMissing ./go.sum)
          (lib.fileset.fileFilter (f: f.hasExt "go") ./.)
        ];
      };
    in
    {
      packages = forAllSystems (system: {
        default = (pkgsFor system).callPackage ./nix/package.nix { inherit src; };
      });

      nixosModules.default = import ./nix/module.nix self;

      # The package's check phase runs `go vet` and `go test` (nix/package.nix). On Linux, the
      # module builds the validated TOML of nix/example.nix, and a typo in it fails the build.
      checks = forAllSystems (
        system:
        let
          moduleConfig =
            extra:
            (lib.nixosSystem {
              modules = [
                self.nixosModules.default
                ./nix/example.nix
                extra
                { nixpkgs.hostPlatform = system; }
              ];
            }).config.environment.etc."genkan/genkan.toml".source;
        in
        {
          default = self.packages.${system}.default;
        }
        // lib.optionalAttrs (lib.hasSuffix "-linux" system) {
          module = moduleConfig { };
          module-typo = (pkgsFor system).testers.testBuildFailure (moduleConfig {
            services.genkan.settings.log.levle = "info";
          });
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShellNoCC {
            packages = [
              pkgs.go
              pkgs.gopls
            ];
          };
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt-tree);
    };
}
