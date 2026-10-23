# NixOS module for genkan (ADR 0002 shape, ADR 0003 lifecycle, ADR 0006 identity and hardening).
# Generates the TOML of docs/config.md, validates it at build time, and runs genkan.service.
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.services.genkan;
  toml = pkgs.formats.toml { };
  exe = lib.getExe cfg.package;
  path = "/etc/genkan/genkan.toml";
  hanko = lib.optional (config.services.hanko.enable or false) "hanko.service";

  # Certificate for a site: exact name first, then a wildcard on the first label.
  certFor =
    host: site:
    let
      parts = lib.splitString "." host;
      wildcard = lib.concatStringsSep "." ([ "*" ] ++ lib.tail parts);
      find =
        name:
        lib.findFirst (n: lib.elem name cfg.certificates.${n}.hosts) null (lib.attrNames cfg.certificates);
      found = if find host != null then find host else find wildcard;
    in
    if site.certificate != null then
      site.certificate
    else if found != null then
      found
    else
      throw "services.genkan.sites.\"${host}\": no certificate covers this host; declare one or set `certificate`";

  generated = {
    listeners = lib.mapAttrsToList (name: l: {
      inherit name;
      addr = l.address;
      mode = "tls";
    }) cfg.listeners;

    certificates = lib.mapAttrs (_: c: { inherit (c) cert key; }) cfg.certificates;

    routes = lib.mapAttrsToList (
      host: site:
      {
        name = host;
        listeners = if site.listeners != null then site.listeners else lib.attrNames cfg.listeners;
        hosts = [ host ];
        certificate = certFor host site;
      }
      // lib.optionalAttrs (site.quietPaths != [ ]) { quiet_paths = site.quietPaths; }
      // (
        if site.root != null then
          {
            type = "static";
            root = "${site.root}"; # a Nix path or package lands in the store
          }
        else
          {
            type = "http";
            inherit (site) backend;
          }
      )
    ) cfg.sites;
  };

  # `genkan validate` at build time: an invalid config never becomes a system (ADR 0003).
  configFile =
    let
      raw = toml.generate "genkan.toml" cfg.settings;
    in
    pkgs.runCommand "genkan.toml" { } ''
      ${exe} validate ${raw}
      cp ${raw} $out
    '';
in
{
  options.services.genkan = {
    enable = lib.mkEnableOption "genkan, the homelab reverse proxy";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "genkan.packages.\${system}.default";
      description = "The genkan package.";
    };

    listeners = mkOption {
      type = types.attrsOf (
        types.submodule {
          options.address = mkOption {
            type = types.str;
            example = "[fd42::10]:443";
            description = "Go `host:port` to bind; `:443` binds every address.";
          };
        }
      );
      default.default.address = ":443";
      description = "TLS listeners, by name. Sites use all of them unless they list some.";
    };

    certificates = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
            hosts = mkOption {
              type = types.listOf types.str;
              example = [ "*.home.example.org" ];
              description = "Hosts this certificate covers; sites are matched to it by host.";
            };
            cert = mkOption {
              type = types.str;
              example = "/var/lib/hanko/home/fullchain.pem";
              description = "Path to the PEM certificate chain, leaf first (written by hanko, or a sops secret path).";
            };
            key = mkOption {
              type = types.str;
              example = "/var/lib/hanko/home/key.pem";
              description = "Path to the PEM private key (written by hanko, or a sops secret path, never a value).";
            };
          };
        }
      );
      default = { };
      description = "Certificates, by name. Sites are matched to them by host.";
    };

    sites = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
            backend = mkOption {
              type = types.nullOr types.str;
              default = null;
              example = "http://127.0.0.1:3000";
              description = "`http://host:port` the requests are forwarded to. Exclusive with `root`.";
            };
            root = mkOption {
              type = types.nullOr types.path;
              default = null;
              example = lib.literalExpression "pkgs.my-site";
              description = ''
                Absolute directory (or a package) served as static files: `index.html` for a directory, 404
                otherwise, no listing. Must be readable by the `genkan` user. Exclusive with `backend`.
              '';
            };
            listeners = mkOption {
              type = types.nullOr (types.listOf types.str);
              default = null;
              description = "Listener names; null means every listener.";
            };
            certificate = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "Certificate name; null picks the one whose hosts match, exact name before wildcard.";
            };
            quietPaths = mkOption {
              type = types.listOf types.str;
              default = [ ];
              example = [ "/api/actions/runner.v1.RunnerService/FetchTask" ];
              description = ''
                Exact request paths (no query) whose `request` line is not written when the status is
                below 400; failures are still logged, metrics count them all (ADR 0011).
              '';
            };
          };
        }
      );
      default = { };
      description = "Sites, by hostname: an HTTP backend or a static root.";
    };

    metrics.listen = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "127.0.0.1:9101";
      description = ''
        Loopback `127.0.0.1:<port>` or `[::1]:<port>` serving `GET /metrics` for the local agent
        (ADR 0008); null serves no metrics. Bound at start only: a change restarts genkan.
      '';
    };

    settings = mkOption {
      inherit (toml) type;
      default = { };
      description = ''
        The TOML of docs/config.md. The options above are merged into it; definitions here add to
        them (lists concatenate) and `lib.mkForce` replaces them.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions =
      lib.mapAttrsToList (host: site: {
        assertion = (site.backend != null) != (site.root != null);
        message = "services.genkan.sites.\"${host}\": set exactly one of backend and root.";
      }) cfg.sites
      ++ [
        {
          assertion =
            cfg.metrics.listen == null
            || builtins.match "(127\\.0\\.0\\.1|\\[::1]):[0-9]+" cfg.metrics.listen != null;
          message = "services.genkan.metrics.listen: must be 127.0.0.1:<port> or [::1]:<port> (loopback only, ADR 0008).";
        }
      ];

    services.genkan.settings = {
      log = lib.mapAttrs (_: lib.mkDefault) {
        level = "info";
        access = true;
      };
      inherit (generated) listeners certificates routes;
    }
    // lib.optionalAttrs (cfg.metrics.listen != null) { metrics.listen = cfg.metrics.listen; };

    environment.etc."genkan/genkan.toml".source = configFile;

    users.users.genkan = {
      isSystemUser = true;
      group = "genkan";
    };
    users.groups.genkan = { };

    systemd.services.genkan = {
      description = "genkan reverse proxy";
      wantedBy = [ "multi-user.target" ];
      # hanko (a oneshot that stays active) has written its certificates before genkan reads them;
      # a pair still missing then is "not ready", not fatal (ADR 0009). Only when hanko runs here.
      wants = [ "network-online.target" ] ++ hanko;
      after = [ "network-online.target" ] ++ hanko;
      # ExecStart reads /etc, so a config change reloads instead of restarting.
      reloadTriggers = [ configFile ];
      # Except the metrics listener, which a reload does not move (ADR 0008): the merged value, so
      # `settings.metrics.listen` restarts too.
      restartTriggers = [ (cfg.settings.metrics.listen or "") ];
      serviceConfig = {
        Type = "notify";
        ExecStart = "${exe} run ${path}";
        ExecReload = [
          "${exe} validate ${path}"
          "${pkgs.coreutils}/bin/kill -HUP $MAINPID"
        ];
        Restart = "on-failure";
        User = "genkan";
        Group = "genkan";
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        LimitNOFILE = 65536;
        # One line per request: 1000 lines/s sustained before journald drops (nisshi ADR 0009).
        LogRateLimitIntervalSec = lib.mkDefault "30s";
        LogRateLimitBurst = lib.mkDefault 30000;
      };
    };
  };
}
