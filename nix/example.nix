# Sample configuration for the module checks in flake.nix: the v0.3 target on ishizue, with
# illustrative names. Building its /etc/genkan/genkan.toml runs `genkan validate` on it.
{
  system.stateVersion = "26.05";

  services.genkan = {
    enable = true;
    listeners.lan.address = "[fd42::10]:443";
    listeners.edge.address = "[fd42::10]:8443";
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
    sites."site.home.example.org".root = "/var/www/site";
  };
}
