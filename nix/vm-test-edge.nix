# NixOS VM test (milestone v1.0): two genkan instances and a client. The edge forwards public
# HTTPS by SNI, raw and behind a PROXY v2 header, to the homelab's PROXY listener, and git SSH by
# port without the header. The homelab terminates TLS: its backend sees the client's address.
# Also: an internal host is not reachable through a public SNI (G8), unknown SNI is closed on the
# edge, an untrusted peer is closed on the PROXY listener, half-close crosses the edge, a reload
# keeps passthrough, port 80 on the edge redirects (v1.1), and both instances' logs and metrics
# pass nisshi and masu.
self:
{
  pkgs,
  nisshi,
  masu,
  ...
}:
let
  system = pkgs.stdenv.hostPlatform.system;
  validateLogs = nisshi.lib.validateLogs.${system};
  validateMetrics = masu.lib.validateMetrics.${system};
  metrics = "127.0.0.1:9101";

  certs = pkgs.runCommand "genkan-edge-test-certs" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir $out && cd $out
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=genkan-test-ca \
      -keyout ca.key -out ca.pem
    openssl req -newkey rsa:2048 -nodes -subj /CN=homelab -keyout leaf.key -out leaf.csr
    openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 3650 \
      -extfile <(printf 'subjectAltName=DNS:app.test,DNS:internal.test') -out leaf.pem
  '';

  # Echoes what genkan forwarded.
  backend = pkgs.writeText "backend.py" ''
    from http.server import BaseHTTPRequestHandler, HTTPServer


    class Echo(BaseHTTPRequestHandler):
        def do_GET(self):
            h = self.headers
            body = "host=%s for=%s proto=%s fhost=%s" % (
                h["Host"], h["X-Forwarded-For"], h["X-Forwarded-Proto"], h["X-Forwarded-Host"])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body.encode())


    HTTPServer(("127.0.0.1", 8080), Echo).serve_forever()
  '';

  # Stands in for git SSH: reads to the client's half-close, answers with what it read and the
  # address it was reached from, then closes.
  sshBackend = pkgs.writeText "ssh-backend.py" ''
    import socket

    server = socket.create_server(("0.0.0.0", 2222))
    while True:
        conn, (peer, _) = server.accept()
        data = b""
        while chunk := conn.recv(4096):
            data += chunk
        conn.sendall(data + b" from " + peer.encode())
        conn.close()
  '';

  sshClient = pkgs.writeText "ssh-client.py" ''
    import socket
    import sys

    conn = socket.create_connection((sys.argv[1], 2222), timeout=10)
    conn.sendall(b"ping")
    conn.shutdown(socket.SHUT_WR)
    reply = b""
    while chunk := conn.recv(4096):
        reply += chunk
    sys.stdout.write(reply.decode())
  '';
in
pkgs.testers.runNixOSTest (
  { nodes, ... }:
  let
    edgeIP = nodes.edge.networking.primaryIPAddress;
    homelabIP = nodes.homelab.networking.primaryIPAddress;
    clientIP = nodes.client.networking.primaryIPAddress;
  in
  {
    name = "genkan-edge";

    nodes.client = {
      environment.systemPackages = [
        pkgs.curl
        pkgs.python3
      ];
    };

    nodes.edge = {
      imports = [ self.nixosModules.default ];
      networking.firewall.allowedTCPPorts = [
        80
        443
        2222
      ];
      services.genkan = {
        enable = true;
        httpRedirect.enable = true;
        listeners.https.address = ":443";
        listeners.ssh.address = ":2222";
        passthrough.homelab-https = {
          listener = "https";
          sni = [ "app.test" ];
          backend = "${homelabIP}:8443";
          sendProxy = true;
        };
        passthrough.git-ssh = {
          listener = "ssh";
          backend = "${homelabIP}:2222";
        };
        metrics.listen = metrics;
      };
    };

    nodes.homelab = {
      imports = [ self.nixosModules.default ];
      networking.firewall.allowedTCPPorts = [
        443
        2222
        8443
      ];
      systemd.services.backend = {
        wantedBy = [ "multi-user.target" ];
        before = [ "genkan.service" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${backend}";
      };
      systemd.services.ssh-backend = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${sshBackend}";
      };
      services.genkan = {
        enable = true;
        listeners.lan.address = ":443";
        listeners.edge = {
          address = ":8443";
          acceptProxy = true;
          trustedSources = [ "${edgeIP}/32" ];
        };
        # A test key in the store is fine; real ones are hanko's files (ADR 0004).
        certificates.test = {
          hosts = [
            "app.test"
            "internal.test"
          ];
          cert = "${certs}/leaf.pem";
          key = "${certs}/leaf.key";
        };
        sites."app.test" = {
          backend = "http://127.0.0.1:8080";
          listeners = [
            "lan"
            "edge"
          ];
        };
        sites."internal.test".backend = "http://127.0.0.1:8080"; # lan only (G8)
        metrics.listen = metrics;
      };
    };

    testScript = ''
      EDGE, HOMELAB, CLIENT = "${edgeIP}", "${homelabIP}", "${clientIP}"
      journal = "journalctl _SYSTEMD_UNIT=genkan.service -o cat"

      def curl(host, ip, extra=""):
          return client.succeed(
              f"curl -sS --cacert ${certs}/ca.pem --resolve {host}:443:{ip} {extra} "
              f"-w ' %{{http_code}}' https://{host}/"
          )

      start_all()
      homelab.wait_for_unit("backend.service")
      homelab.wait_for_unit("ssh-backend.service")
      homelab.wait_for_open_port(2222)
      # Type=notify: ready once every listener is bound. No wait_for_open_port on genkan's ports, its
      # probes would be connections too.
      homelab.wait_for_unit("genkan.service")
      edge.wait_for_unit("genkan.service")
      client.wait_for_unit("multi-user.target")

      with subtest("public HTTPS through the edge: the backend sees the client's address"):
          # --cacert: TLS ended on the homelab with its certificate, not on the edge.
          out = curl("app.test", EDGE)
          assert out == f"host=app.test for={CLIENT} proto=https fhost=app.test 200", out

      with subtest("a public SNI does not reach a host the PROXY listener does not serve (G8)"):
          out = curl("app.test", EDGE, "-H 'Host: internal.test'")
          assert out.endswith(" 404"), out
          out = curl("internal.test", HOMELAB)
          assert out == f"host=internal.test for={CLIENT} proto=https fhost=internal.test 200", out

      with subtest("unknown SNI on the edge is closed"):
          client.fail(f"curl -sS -k --resolve internal.test:443:{EDGE} https://internal.test/")

      with subtest("the PROXY listener closes a peer outside trusted_sources"):
          client.fail(f"curl -sS -k --resolve app.test:8443:{HOMELAB} https://app.test:8443/")

      with subtest("port 80 on the edge redirects to https, nothing forwarded (v1.1)"):
          out = client.succeed(f"curl -sSI -H 'Host: app.test' http://{EDGE}/p?q=1")
          assert out.startswith("HTTP/1.1 301"), out
          assert "Location: https://app.test/p?q=1\r\n" in out, out

      with subtest("git SSH by port, without PROXY header, half-close carried both ways"):
          out = client.succeed(f"python3 ${sshClient} {EDGE}")
          assert out == f"ping from {EDGE}", out

      with subtest("a reload keeps passthrough"):
          edge.succeed("systemctl reload genkan")
          edge.wait_until_succeeds(f"{journal} | grep -F '\"event\":\"reloaded\"'")
          assert curl("app.test", EDGE).endswith(" 200")

      with subtest("every log line passes the log schema"):
          for machine, lines in [
              (edge, [
                  ['"event":"connection"', '"route":"homelab-https"', f'"client":"{CLIENT}"', '"sni":"app.test"'],
                  ['"event":"connection"', '"route":"git-ssh"', f'"client":"{CLIENT}"', '"sni":"-"'],
                  ['"event":"connection-rejected"', '"listener":"https"', '"reason":"unknown-sni"'],
                  ['"event":"request"', '"listener":"http-redirect"', '"route":"-"', '"status":301'],
              ]),
              (homelab, [
                  ['"event":"request"', '"listener":"edge"', '"route":"app.test"', f'"client":"{CLIENT}"'],
                  ['"event":"connection-rejected"', '"listener":"edge"', '"reason":"untrusted-peer"'],
              ]),
          ]:
              for fields in lines:
                  machine.wait_until_succeeds(journal + "".join(f" | grep -F '{x}'" for x in fields))
              machine.succeed(f"{journal} | ${validateLogs} validate --logs")

      with subtest("metrics pass the metric convention and count passthrough"):
          for machine in [edge, homelab]:
              machine.succeed("${validateMetrics} validate --metrics http://${metrics}/metrics")
          out = edge.succeed("curl -sS http://${metrics}/metrics")
          assert 'genkan_connections_total{listener="https",route="homelab-https"} ' in out, out
          assert 'genkan_connections_total{listener="ssh",route="git-ssh"} 1' in out, out
          assert 'genkan_connections_rejected_total{listener="https",reason="unknown-sni"} 1' in out, out
          out = homelab.succeed("curl -sS http://${metrics}/metrics")
          assert 'genkan_connections_rejected_total{listener="edge",reason="untrusted-peer"} 1' in out, out
    '';
  }
)
