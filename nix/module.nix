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

  # A listener whose passthrough route has no SNI forwards the whole port: mode tcp.
  tcpListeners = lib.mapAttrsToList (_: p: p.listener) (
    lib.filterAttrs (_: p: p.sni == [ ]) cfg.passthrough
  );
  modeOf = name: if lib.elem name tcpListeners then "tcp" else "tls";

  # Where a site goes without `listeners`: TLS listeners that do not accept PROXY headers. A
  # listener fed by the edge serves only the sites that name it (G8, ADR 0013).
  siteListeners = lib.attrNames (
    lib.filterAttrs (name: l: modeOf name == "tls" && !l.acceptProxy) cfg.listeners
  );

  generated = {
    listeners =
      lib.mapAttrsToList (
        name: l:
        {
          inherit name;
          addr = l.address;
          mode = modeOf name;
        }
        // lib.optionalAttrs l.acceptProxy {
          accept_proxy = "required";
          trusted_sources = l.trustedSources;
        }
      ) cfg.listeners
      # Outside `listeners`: enabling it neither replaces the default listener nor receives sites.
      ++ lib.optional cfg.httpRedirect.enable {
        name = "http-redirect";
        addr = cfg.httpRedirect.address;
        mode = "http";
      };

    certificates = lib.mapAttrs (_: c: { inherit (c) cert key; }) cfg.certificates;

    routes =
      lib.mapAttrsToList (
        host: site:
        {
          name = host;
          listeners = if site.listeners != null then site.listeners else siteListeners;
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
      ) cfg.sites
      ++ lib.mapAttrsToList (
        name: p:
        {
          inherit name;
          type = "tcp";
          listeners = [ p.listener ];
          inherit (p) backend;
        }
        // lib.optionalAttrs (p.sni != [ ]) { inherit (p) sni; }
        // lib.optionalAttrs p.sendProxy { send_proxy = "v2"; }
      ) cfg.passthrough;
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
          options = {
            address = mkOption {
              type = types.str;
              example = "[fd42::10]:443";
              description = "Go `host:port` to bind; `:443` binds every address.";
            };
            acceptProxy = mkOption {
              type = types.bool;
              default = false;
              description = ''
                Require a PROXY protocol v2 header on every connection, from a peer in
                `trustedSources`; anything else is closed before a byte is read. The header's client
                address is what access logs and `X-Forwarded-For` show. Sites are not served here
                unless they list this listener.
              '';
            };
            trustedSources = mkOption {
              type = types.listOf types.str;
              default = [ ];
              example = [ "fd42::1/128" ];
              description = "CIDRs allowed to send PROXY headers; required with `acceptProxy`.";
            };
          };
        }
      );
      default.default.address = ":443";
      description = ''
        Listeners, by name. A listener is `tcp` (whole port forwarded) when a passthrough route
        without `sni` uses it, `tls` otherwise. Sites without `listeners` use every `tls` listener
        that does not accept PROXY headers. Declaring any listener replaces the default one: add
        `default.address = ":443"` back if it is still wanted.
      '';
    };

    httpRedirect = {
      enable = lib.mkEnableOption ''
        a plaintext listener named `http-redirect` answering every request with a 301 to
        `https://` on the same host and path. It is not one of `listeners`: enabling it keeps the
        default listener, and no site or passthrough may use it
      '';
      address = mkOption {
        type = types.str;
        default = ":80";
        description = "Go `host:port` the redirect listener binds; `:80` binds every address.";
      };
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

    passthrough = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
            listener = mkOption {
              type = types.str;
              description = "Listener name.";
            };
            sni = mkOption {
              type = types.listOf types.str;
              default = [ ];
              example = [ "git.example.org" ];
              description = ''
                Server names forwarded raw, TLS left to the backend. Empty: the whole port goes to
                the backend, uninspected, and the listener becomes `tcp` (no site may use it).
              '';
            };
            backend = mkOption {
              type = types.str;
              example = "[fd42::10]:8443";
              description = "`host:port` the stream is forwarded to.";
            };
            sendProxy = mkOption {
              type = types.bool;
              default = false;
              description = ''
                Prefix the backend connection with a PROXY protocol v2 header carrying the client
                address. Only for a backend that requires it: git SSH, reached from the LAN too,
                goes without (ADR 0002).
              '';
            };
          };
        }
      );
      default = { };
      description = "Raw TCP routes (edge role), by name.";
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
