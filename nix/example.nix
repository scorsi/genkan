# Sample configuration for the module checks in flake.nix: the v0.2 target on ishizue, with
# illustrative names. Building its /etc/genkan/genkan.toml runs `genkan validate` on it.
{
  system.stateVersion = "26.05";

  security.acme = {
    acceptTerms = true;
    defaults.email = "admin@example.org";
    certs."home.example.org" = {
      domain = "*.home.example.org";
      dnsProvider = "porkbun";
    };
  };

  services.genkan = {
    enable = true;
    listeners.lan.address = "[fd42::10]:443";
    certificates.home.useACMEHost = "home.example.org";
    sites."git.home.example.org".backend = "http://127.0.0.1:3000";
    sites."site.home.example.org".backend = "http://127.0.0.1:8080";
  };
}
