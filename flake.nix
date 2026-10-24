{
  description = "genkan (玄関, the entrance) — reverse proxy for a Nix-managed homelab: package, NixOS module, dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";

    # Test-only: the VM test runs their validators on genkan's logs and metrics (ADR 0008).
    nisshi = {
      url = "git+ssh://git@forgejo.uchi.scorsi.dev:2222/scorsi/nisshi.git";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    masu = {
      url = "git+ssh://git@forgejo.uchi.scorsi.dev:2222/scorsi/masu.git";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      nisshi,
      masu,
      ...
    }:
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
      # module builds the validated TOML of nix/example.nix, a typo in it fails the build, and the
      # VM tests of nix/vm-test.nix and nix/vm-test-edge.nix run (need a Linux builder: Forgejo CI).
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

          # Unit wiring, evaluated only (runs on darwin too): start after hanko when it runs here, and
          # restart on any change of the metrics address, whichever option sets it.
          module-unit =
            let
              unit =
                extra:
                (lib.nixosSystem {
                  modules = [
                    self.nixosModules.default
                    ./nix/example.nix
                    extra
                    { nixpkgs.hostPlatform = if lib.hasSuffix "-linux" system then system else "aarch64-linux"; }
                  ];
                }).config.systemd.services.genkan;
              withHanko = unit {
                options.services.hanko.enable = lib.mkEnableOption "a stand-in for hanko's module";
                config.services.hanko.enable = true;
              };
              trigger = extra: (unit extra).restartTriggers;
              none = trigger { };
              option = trigger { services.genkan.metrics.listen = "127.0.0.1:9101"; };
              raw = trigger { services.genkan.settings.metrics.listen = "127.0.0.1:9101"; };
              moved = trigger { services.genkan.settings.metrics.listen = "127.0.0.1:9102"; };
              settings =
                extra:
                (lib.nixosSystem {
                  modules = [
                    self.nixosModules.default
                    ./nix/example.nix
                    extra
                    { nixpkgs.hostPlatform = if lib.hasSuffix "-linux" system then system else "aarch64-linux"; }
                  ];
                }).config.services.genkan.settings;
              homelab = settings { };
              routeOf = s: name: lib.findFirst (r: r.name == name) null s.routes;
              listenerOf = s: name: lib.findFirst (l: l.name == name) null s.listeners;
              # The edge role of ADR 0002 on top of the sample.
              edge = settings {
                services.genkan.listeners.public-https.address = ":443";
                services.genkan.listeners.public-ssh.address = ":2222";
                services.genkan.passthrough.homelab-https = {
                  listener = "public-https";
                  sni = [ "cv.home.example.org" ];
                  backend = "[fd42::10]:8443";
                  sendProxy = true;
                };
                services.genkan.passthrough.git-ssh = {
                  listener = "public-ssh";
                  backend = "[fd42::10]:2222";
                };
              };
            in
            assert lib.assertMsg (
              lib.elem "hanko.service" withHanko.after && lib.elem "hanko.service" withHanko.wants
            ) "genkan is not ordered after hanko";
            assert lib.assertMsg (!lib.elem "hanko.service" (unit { }).after) "hanko ordering without hanko";
            assert lib.assertMsg (
              option == raw && none != raw && raw != moved
            ) "metrics address changes do not all restart genkan";
            # G8: a site without `listeners` stays off the PROXY listener; one that names it is there.
            assert lib.assertMsg (
              (routeOf homelab "site.home.example.org").listeners == [ "lan" ]
              &&
                (routeOf homelab "cv.home.example.org").listeners == [
                  "lan"
                  "edge"
                ]
              && (listenerOf homelab "edge").accept_proxy == "required"
              && (listenerOf homelab "edge").trusted_sources == [ "fd42::1/128" ]
            ) "sites default to the PROXY listener";
            # Passthrough: SNI routes on a tls listener, a route without SNI makes its listener tcp,
            # and sites stay off tcp listeners.
            assert lib.assertMsg (
              (listenerOf edge "public-https").mode == "tls"
              && (listenerOf edge "public-ssh").mode == "tcp"
              &&
                routeOf edge "homelab-https" == {
                  name = "homelab-https";
                  type = "tcp";
                  listeners = [ "public-https" ];
                  sni = [ "cv.home.example.org" ];
                  backend = "[fd42::10]:8443";
                  send_proxy = "v2";
                }
              &&
                routeOf edge "git-ssh" == {
                  name = "git-ssh";
                  type = "tcp";
                  listeners = [ "public-ssh" ];
                  backend = "[fd42::10]:2222";
                }
              &&
                (routeOf edge "site.home.example.org").listeners == [
                  "lan"
                  "public-https"
                ]
            ) "passthrough routes or listener modes are wrong";
            (pkgsFor system).runCommand "genkan-module-unit" { } "touch $out";
        }
        // lib.optionalAttrs (lib.hasSuffix "-linux" system) {
          module = moduleConfig { };
          module-typo = (pkgsFor system).testers.testBuildFailure (moduleConfig {
            services.genkan.settings.log.levle = "info";
          });
          vm = import ./nix/vm-test.nix self {
            pkgs = pkgsFor system;
            inherit nisshi masu;
          };
          vm-edge = import ./nix/vm-test-edge.nix self {
            pkgs = pkgsFor system;
            inherit nisshi masu;
          };
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
