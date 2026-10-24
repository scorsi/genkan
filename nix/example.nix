# Sample configuration for the module checks in flake.nix: the v1.0 homelab role on ishizue, with
# illustrative names: the LAN listener, and the overlay listener fed by the edge. Building its /etc/genkan/genkan.toml runs `genkan validate` on it.
{
  system.stateVersion = "26.05";

  services.genkan = {
    enable = true;
    listeners.lan.address = "[fd42::10]:443";
    listeners.edge = {
      address = "[fd42::10]:8443";
      acceptProxy = true;
      trustedSources = [ "fd42::1/128" ];
    };
    certificates.home = {
      hosts = [ "*.home.example.org" ];
      cert = "/var/lib/hanko/home/fullchain.pem";
      key = "/var/lib/hanko/home/key.pem";
    };
    sites."git.home.example.org" = {
      backend = "http://127.0.0.1:3000";
      listeners = [ "lan" ];
      quietPaths = [ "/api/actions/runner.v1.RunnerService/FetchTask" ];
    };
    # Not public: without `listeners`, a site stays off the PROXY listener (G8).
    sites."site.home.example.org".root = "/var/www/site";
    sites."cv.home.example.org" = {
      root = "/var/www/cv";
      listeners = [
        "lan"
        "edge"
      ];
    };
  };
}
