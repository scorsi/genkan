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

  acmeHosts = lib.unique (
    lib.filter (h: h != null) (lib.mapAttrsToList (_: c: c.useACMEHost) cfg.certificates)
  );

  # Hosts a certificate covers: declared, or the names security.acme issues it for.
  certHosts =
    c:
    if c.useACMEHost != null then
      let
        acme = config.security.acme.certs.${c.useACMEHost};
      in
      [ acme.domain ] ++ acme.extraDomainNames
    else
      c.hosts;

  # Certificate for a site: exact name first, then a wildcard on the first label.
  certFor =
    host: site:
    let
      parts = lib.splitString "." host;
      wildcard = lib.concatStringsSep "." ([ "*" ] ++ lib.tail parts);
      find =
        name:
        lib.findFirst (n: lib.elem name (certHosts cfg.certificates.${n})) null (
          lib.attrNames cfg.certificates
        );
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

    certificates = lib.mapAttrs (
      _: c:
      if c.useACMEHost != null then
        let
          dir = config.security.acme.certs.${c.useACMEHost}.directory;
        in
        {
          cert = "${dir}/fullchain.pem";
          key = "${dir}/key.pem";
        }
      else
        { inherit (c) cert key; }
    ) cfg.certificates;

    routes = lib.mapAttrsToList (host: site: {
      name = host;
      type = "http";
      listeners = if site.listeners != null then site.listeners else lib.attrNames cfg.listeners;
      hosts = [ host ];
      certificate = certFor host site;
      inherit (site) backend;
    }) cfg.sites;
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
            useACMEHost = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                A `security.acme.certs` entry. Its domain and extra domain names give the hosts it
                covers, genkan joins the `acme` group, and the certificate reloads genkan on renewal.
              '';
            };
            hosts = mkOption {
              type = types.listOf types.str;
              default = [ ];
              example = [ "*.home.example.org" ];
              description = "Hosts this certificate covers, when it does not come from `useACMEHost`.";
            };
            cert = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "Path to the PEM certificate chain (a sops secret path, never a value).";
            };
            key = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "Path to the PEM private key (a sops secret path, never a value).";
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
              type = types.str;
              example = "http://127.0.0.1:3000";
              description = "`http://host:port` the requests are forwarded to.";
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
          };
        }
      );
      default = { };
      description = "HTTP sites, by hostname.";
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
    assertions = lib.mapAttrsToList (name: c: {
      assertion = (c.useACMEHost != null) != (c.cert != null && c.key != null);
      message = "services.genkan.certificates.${name}: set either useACMEHost or both cert and key.";
    }) cfg.certificates;

    services.genkan.settings = {
      log = lib.mapAttrs (_: lib.mkDefault) {
        level = "info";
        access = true;
      };
      inherit (generated) listeners certificates routes;
    };

    environment.etc."genkan/genkan.toml".source = configFile;

    users.users.genkan = {
      isSystemUser = true;
      group = "genkan";
    };
    users.groups.genkan = { };

    security.acme.certs = lib.genAttrs acmeHosts (_: {
      reloadServices = [ "genkan.service" ];
    });

    systemd.services.genkan = {
      description = "genkan reverse proxy";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ] ++ map (h: "acme-${h}.service") acmeHosts;
      after = [ "network-online.target" ] ++ map (h: "acme-${h}.service") acmeHosts;
      # ExecStart reads /etc, so a config change reloads instead of restarting.
      reloadTriggers = [ configFile ];
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
        SupplementaryGroups = lib.optional (acmeHosts != [ ]) "acme";
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        StateDirectory = "genkan";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        LimitNOFILE = 65536;
      };
    };
  };
}
