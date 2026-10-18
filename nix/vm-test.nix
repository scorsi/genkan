# NixOS VM test (milestone v0.3): genkan in front of one HTTP backend and one static root, two
# hostnames, self-signed certificates. curl asserts routing, forwarding headers, unknown SNI, a
# certificate rotation picked up by `systemctl reload`, and a failed reload that keeps serving.
self:
{ pkgs, ... }:
let
  # A CA, a leaf for both hosts, and a second leaf with another subject for the rotation.
  certs = pkgs.runCommand "genkan-test-certs" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir $out && cd $out
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=genkan-test-ca \
      -keyout ca.key -out ca.pem
    for leaf in first rotated; do
      openssl req -newkey rsa:2048 -nodes -subj /CN=$leaf -keyout $leaf.key -out $leaf.csr
      openssl x509 -req -in $leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 3650 \
        -extfile <(printf 'subjectAltName=DNS:app.test,DNS:site.test') -out $leaf.pem
    done
  '';

  site = pkgs.runCommand "genkan-test-site" { } ''
    mkdir -p $out/docs $out/bare
    echo home > $out/index.html
    echo docs > $out/docs/index.html
    echo x > $out/bare/x.txt
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

  dir = "/var/lib/hanko/test"; # where hanko writes, group genkan per certificate
in
pkgs.testers.runNixOSTest {
  name = "genkan";

  nodes.machine = {
    imports = [ self.nixosModules.default ];

    systemd.services.backend = {
      wantedBy = [ "multi-user.target" ];
      before = [ "genkan.service" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${backend}";
    };

    # The test stands in for hanko (certificate group = genkan's own group) and copies the
    # files out of the store so it can rotate them.
    systemd.tmpfiles.rules = [
      "d /var/lib/hanko 0755 root root -"
      "d ${dir} 2750 root genkan -"
      "C ${dir}/fullchain.pem 0640 root genkan - ${certs}/first.pem"
      "C ${dir}/key.pem 0640 root genkan - ${certs}/first.key"
    ];

    services.genkan = {
      enable = true;
      certificates.test = {
        hosts = [
          "app.test"
          "site.test"
        ];
        cert = "${dir}/fullchain.pem";
        key = "${dir}/key.pem";
      };
      sites."app.test".backend = "http://127.0.0.1:8080";
      sites."site.test".root = site;
    };

    environment.systemPackages = [
      pkgs.curl
      pkgs.openssl
    ];
  };

  testScript = ''
    def curl(host, path="/", extra=""):
        return machine.succeed(
            f"curl -sS --cacert ${certs}/ca.pem --resolve {host}:443:127.0.0.1 {extra} "
            f"-w ' %{{http_code}}' https://{host}{path}"
        )

    def subject():
        return machine.succeed(
            "openssl s_client -connect 127.0.0.1:443 -servername app.test </dev/null 2>/dev/null"
            " | openssl x509 -noout -subject"
        )

    machine.wait_for_unit("backend.service")
    machine.wait_for_unit("genkan.service")
    machine.wait_for_open_port(443)

    with subtest("http route with trusted forwarding headers"):
        out = curl("app.test", extra="-H 'X-Forwarded-For: 6.6.6.6' -H 'X-Forwarded-Host: evil'")
        assert out == "host=app.test for=127.0.0.1 proto=https fhost=app.test 200", out

    with subtest("static route"):
        assert curl("site.test") == "home\n 200"
        assert curl("site.test", "/docs/") == "docs\n 200"
        assert curl("site.test", "/bare/x.txt") == "x\n 200"
        assert curl("site.test", "/bare/").endswith(" 404"), "directory listing served"
        assert curl("site.test", "/missing").endswith(" 404")

    with subtest("unknown SNI fails the handshake"):
        machine.fail("curl -sS -k --resolve other.test:443:127.0.0.1 https://other.test/")

    pid = machine.succeed("systemctl show -P MainPID genkan").strip()

    with subtest("reload picks up a rotated certificate"):
        assert "first" in subject()
        machine.succeed("cp ${certs}/rotated.pem ${dir}/fullchain.pem")
        machine.succeed("cp ${certs}/rotated.key ${dir}/key.pem")
        machine.succeed("systemctl reload genkan")
        machine.wait_until_succeeds("openssl s_client -connect 127.0.0.1:443 -servername app.test"
                                    " </dev/null 2>/dev/null | openssl x509 -noout -subject | grep rotated")
        assert curl("site.test") == "home\n 200"

    with subtest("failed reload keeps the running config"):
        machine.succeed("echo garbage > ${dir}/fullchain.pem")
        machine.succeed("systemctl reload genkan")
        machine.wait_until_succeeds("journalctl -u genkan | grep 'reload failed'")
        assert "rotated" in subject()
        assert curl("app.test").endswith(" 200")

    assert machine.succeed("systemctl show -P MainPID genkan").strip() == pid, "genkan restarted"
  '';
}
