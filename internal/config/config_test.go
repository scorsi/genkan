package config

import (
	"strings"
	"testing"
)

const valid = `
[[listeners]]
name = "lan"
addr = "[::1]:8443"
mode = "tls"

[certificates.git]
cert = "/tmp/git.pem"
key = "/tmp/git.key"

[[routes]]
name = "forgejo"
type = "http"
listeners = ["lan"]
hosts = ["git.example.org"]
certificate = "git"
backend = "http://127.0.0.1:3000"
`

func TestValid(t *testing.T) {
	c, err := Parse(strings.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	if c.Log.Level != "info" || !c.Log.Access {
		t.Errorf("defaults: got %+v", c.Log)
	}
	if errs, warns := c.Validate(); len(errs) > 0 || len(warns) > 0 {
		t.Errorf("errs=%v warns=%v", errs, warns)
	}
}

func TestInvalid(t *testing.T) {
	tests := []struct{ name, toml, want string }{
		{"unknown key", valid + "\n[log]\nlevle = \"info\"\n", `unknown key "log.levle"`},
		{"unknown nested key", strings.Replace(valid, `mode = "tls"`, "mode = \"tls\"\nbogus = 1", 1), `unknown key "listeners.bogus"`},
		{"bad level", valid + "\n[log]\nlevel = \"loud\"\n", "log.level"},
		{"no listeners", "[[routes]]\nname = \"x\"\ntype = \"http\"\nlisteners = [\"lan\"]\n", "no listeners"},
		{"dup listener", valid + "\n[[listeners]]\nname = \"lan\"\naddr = \"[::1]:9443\"\nmode = \"tls\"\n", `listener "lan": duplicate name`},
		{"dup addr", valid + "\n[[listeners]]\nname = \"lan2\"\naddr = \"[::1]:8443\"\nmode = \"tls\"\n", `addr "[::1]:8443" already used`},
		{"bad addr", strings.Replace(valid, `"[::1]:8443"`, `"8443"`, 1), "is not host:port"},
		{"bad mode", strings.Replace(valid, `mode = "tls"`, `mode = "udp"`, 1), "mode must be"},
		{"route on http listener", strings.Replace(valid, `mode = "tls"`, `mode = "http"`, 1), `routes cannot reference http listener "lan"`},
		{"accept_proxy on http", valid + "\n[[listeners]]\nname = \"redirect\"\naddr = \":80\"\nmode = \"http\"\naccept_proxy = \"required\"\ntrusted_sources = [\"fd42::1/128\"]\n", `listener "redirect": accept_proxy on an http listener`},
		{"accept_proxy v1", strings.Replace(valid, `mode = "tls"`, "mode = \"tls\"\naccept_proxy = \"v1\"\ntrusted_sources = [\"fd42::1/128\"]", 1), `accept_proxy must be "required"`},
		{"accept_proxy without sources", strings.Replace(valid, `mode = "tls"`, "mode = \"tls\"\naccept_proxy = \"required\"", 1), "accept_proxy needs a non-empty trusted_sources"},
		{"sources without accept_proxy", strings.Replace(valid, `mode = "tls"`, "mode = \"tls\"\ntrusted_sources = [\"fd42::1/128\"]", 1), "trusted_sources without accept_proxy"},
		{"source not a CIDR", strings.Replace(valid, `mode = "tls"`, "mode = \"tls\"\naccept_proxy = \"required\"\ntrusted_sources = [\"fd42::1\"]", 1), `trusted_sources "fd42::1" is not a CIDR`},
		{"accept_proxy no sources", strings.Replace(valid, `mode = "tls"`, "mode = \"tls\"\naccept_proxy = \"required\"", 1), "non-empty trusted_sources"},
		{"sources without accept_proxy", strings.Replace(valid, `mode = "tls"`, "mode = \"tls\"\ntrusted_sources = [\"fd42::1/128\"]", 1), "trusted_sources without accept_proxy"},
		{"dup route", valid + "\n[[routes]]\nname = \"forgejo\"\ntype = \"http\"\nlisteners = [\"lan\"]\nhosts = [\"b.example.org\"]\ncertificate = \"git\"\nbackend = \"http://127.0.0.1:1\"\n", `route "forgejo": duplicate name`},
		{"empty listeners", strings.Replace(valid, `listeners = ["lan"]`, `listeners = []`, 1), "listeners must be non-empty"},
		{"unknown listener", strings.Replace(valid, `listeners = ["lan"]`, `listeners = ["wan"]`, 1), `unknown listener "wan"`},
		{"unknown certificate", strings.Replace(valid, `certificate = "git"`, `certificate = "cv"`, 1), `unknown certificate "cv"`},
		{"dup host", valid + "\n[[routes]]\nname = \"other\"\ntype = \"http\"\nlisteners = [\"lan\"]\nhosts = [\"git.example.org\"]\ncertificate = \"git\"\nbackend = \"http://127.0.0.1:1\"\n", `"git.example.org" on listener "lan" already claimed by route "forgejo"`},
		{"uppercase host", strings.Replace(valid, `"git.example.org"`, `"Git.example.org"`, 1), "must be lowercase"},
		{"host with port", strings.Replace(valid, `"git.example.org"`, `"git.example.org:443"`, 1), "must not include a port"},
		{"wildcard host", strings.Replace(valid, `"git.example.org"`, `"*.example.org"`, 1), "wildcards not implemented before v1.2"},
		{"https backend", strings.Replace(valid, `http://127.0.0.1:3000`, `https://127.0.0.1:3000`, 1), "must be an http:// URL"},
		{"backend with path", strings.Replace(valid, `http://127.0.0.1:3000`, `http://127.0.0.1:3000/api`, 1), "no path, query or userinfo"},
		{"send_proxy on http", valid + "send_proxy = \"v2\"\n", "send_proxy is only for tcp routes"},
		{"static with backend", strings.Replace(valid, `type = "http"`, "type = \"static\"\nroot = \"/var/www\"", 1), "backend is only for http and tcp routes"},
		{"http with root", valid + "root = \"/var/www\"\n", "root is only for static routes"},
		{"static relative root", strings.Replace(strings.Replace(valid, `type = "http"`, `type = "static"`, 1), `backend = "http://127.0.0.1:3000"`, `root = "www"`, 1), "must be an absolute path"},
		{"sni claimed by an http route", valid + "\n[[routes]]\nname = \"pass\"\ntype = \"tcp\"\nlisteners = [\"lan\"]\nsni = [\"git.example.org\"]\nbackend = \"127.0.0.1:22\"\n", `"git.example.org" on listener "lan" already claimed by route "forgejo"`},
		{"uppercase sni", valid + "\n[[routes]]\nname = \"pass\"\ntype = \"tcp\"\nlisteners = [\"lan\"]\nsni = [\"Pass.example.org\"]\nbackend = \"127.0.0.1:22\"\n", `sni "Pass.example.org" must be lowercase`},
		{"tcp backend not host:port", valid + "\n[[routes]]\nname = \"pass\"\ntype = \"tcp\"\nlisteners = [\"lan\"]\nsni = [\"pass.example.org\"]\nbackend = \"127.0.0.1\"\n", `backend "127.0.0.1" is not host:port`},
		{"send_proxy v1", valid + "\n[[routes]]\nname = \"pass\"\ntype = \"tcp\"\nlisteners = [\"lan\"]\nsni = [\"pass.example.org\"]\nbackend = \"127.0.0.1:22\"\nsend_proxy = \"v1\"\n", `send_proxy must be "v2"`},
		{"tcp route on tls and tcp listeners", valid + "\n[[listeners]]\nname = \"ssh\"\naddr = \":22\"\nmode = \"tcp\"\n\n[[routes]]\nname = \"ssh\"\ntype = \"tcp\"\nlisteners = [\"lan\", \"ssh\"]\nbackend = \"127.0.0.1:22\"\n", "listeners must be all tls or all tcp"},
		{"two routes on a tcp listener", valid + "\n[[listeners]]\nname = \"ssh\"\naddr = \":22\"\nmode = \"tcp\"\n\n[[routes]]\nname = \"a\"\ntype = \"tcp\"\nlisteners = [\"ssh\"]\nbackend = \"127.0.0.1:22\"\n\n[[routes]]\nname = \"b\"\ntype = \"tcp\"\nlisteners = [\"ssh\"]\nbackend = \"127.0.0.1:23\"\n", `listener "ssh": tcp mode needs exactly one route, has 2`},
		{"tcp route without sni on tls", valid + "\n[[routes]]\nname = \"ssh\"\ntype = \"tcp\"\nlisteners = [\"lan\"]\nbackend = \"127.0.0.1:22\"\n", "sni is required on tls listeners"},
		{"tcp listener with http route", strings.Replace(valid, `mode = "tls"`, `mode = "tcp"`, 1), `listener "lan" is tcp, only tcp routes may use it`},
		{"tcp listener without route", valid + "\n[[listeners]]\nname = \"ssh\"\naddr = \":22\"\nmode = \"tcp\"\n", `listener "ssh": tcp mode needs exactly one route, has 0`},
		{"quiet path relative", valid + "quiet_paths = [\"api/poll\"]\n", `quiet_paths "api/poll" must start with /`},
		{"quiet path query", valid + "quiet_paths = [\"/poll?x=1\"]\n", `quiet_paths "/poll?x=1" must be a path`},
		{"quiet path twice", valid + "quiet_paths = [\"/poll\", \"/poll\"]\n", `quiet_paths "/poll" listed twice`},
		{"tcp quiet paths", valid + "\n[[routes]]\nname = \"ssh\"\ntype = \"tcp\"\nlisteners = [\"lan\"]\nsni = [\"ssh.example.org\"]\nbackend = \"127.0.0.1:22\"\nquiet_paths = [\"/\"]\n", "quiet_paths are only for http and static routes"},
		{"bad type", strings.Replace(valid, `type = "http"`, `type = "grpc"`, 1), "type must be"},
		{"public metrics", valid + "\n[metrics]\nlisten = \"0.0.0.0:9100\"\n", "metrics.listen: must be 127.0.0.1:<port> or [::1]:<port>"},
		{"metrics without port", valid + "\n[metrics]\nlisten = \"127.0.0.1\"\n", "metrics.listen"},
		{"missing cert key", strings.Replace(valid, "key = \"/tmp/git.key\"\n", "", 1), "certificates.git: key is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Parse(strings.NewReader(tt.toml))
			if err == nil {
				var errs []error
				errs, _ = c.Validate()
				if len(errs) == 0 {
					t.Fatal("expected an error")
				}
				err = errs[0]
				for _, e := range errs {
					if strings.Contains(e.Error(), tt.want) {
						return
					}
				}
				t.Fatalf("no error contains %q, got %v", tt.want, errs)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %q, want substring %q", err, tt.want)
			}
		})
	}
}

func TestValidMetrics(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:9100", "[::1]:9100"} {
		c, err := Parse(strings.NewReader(valid + "\n[metrics]\nlisten = \"" + addr + "\"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if errs, _ := c.Validate(); len(errs) > 0 || c.Metrics.Listen != addr {
			t.Errorf("%s: errs=%v listen=%q", addr, errs, c.Metrics.Listen)
		}
	}
}

func TestValidHTTP(t *testing.T) {
	c, err := Parse(strings.NewReader(valid + "\n[[listeners]]\nname = \"redirect\"\naddr = \":80\"\nmode = \"http\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if errs, warns := c.Validate(); len(errs) > 0 || len(warns) > 0 {
		t.Errorf("errs=%v warns=%v", errs, warns)
	}
}

func TestValidStatic(t *testing.T) {
	static := strings.Replace(strings.Replace(valid, `type = "http"`, `type = "static"`, 1), `backend = "http://127.0.0.1:3000"`, `root = "/var/www"`, 1)
	c, err := Parse(strings.NewReader(static))
	if err != nil {
		t.Fatal(err)
	}
	if errs, warns := c.Validate(); len(errs) > 0 || len(warns) > 0 {
		t.Errorf("errs=%v warns=%v", errs, warns)
	}
}

func TestWarnings(t *testing.T) {
	c, err := Parse(strings.NewReader(valid + "\n[certificates.unused]\ncert = \"/a\"\nkey = \"/b\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	errs, warns := c.Validate()
	if len(errs) > 0 || len(warns) != 1 || !strings.Contains(warns[0], "certificates.unused") {
		t.Errorf("errs=%v warns=%v", errs, warns)
	}
}

func TestValidQuietPaths(t *testing.T) {
	c, err := Parse(strings.NewReader(valid + "quiet_paths = [\"/api/actions/runner.v1.RunnerService/FetchTask\", \"/\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if errs, _ := c.Validate(); len(errs) > 0 || len(c.Routes[0].QuietPaths) != 2 {
		t.Errorf("errs=%v quiet_paths=%q", errs, c.Routes[0].QuietPaths)
	}
}

// The edge of ADR 0002: SNI passthrough with PROXY v2 next to a whole-port tcp listener, and the
// homelab listener that accepts the header.
const edge = `
[[listeners]]
name = "public-https"
addr = ":443"
mode = "tls"

[[listeners]]
name = "public-ssh"
addr = ":2222"
mode = "tcp"

[[listeners]]
name = "from-edge"
addr = "[fd42::10]:8443"
mode = "tls"
accept_proxy = "required"
trusted_sources = ["fd42::1/128", "192.0.2.0/24"]

[[routes]]
name = "homelab-https"
type = "tcp"
listeners = ["public-https"]
sni = ["git.example.org", "cv.example.org"]
backend = "[fd42::10]:8443"
send_proxy = "v2"

[[routes]]
name = "git-ssh"
type = "tcp"
listeners = ["public-ssh"]
backend = "[fd42::10]:2222"

[[routes]]
name = "relay"
type = "tcp"
listeners = ["from-edge"]
sni = ["git.example.org"]
backend = "127.0.0.1:8443"
`

func TestValidL4(t *testing.T) {
	c, err := Parse(strings.NewReader(edge))
	if err != nil {
		t.Fatal(err)
	}
	if errs, warns := c.Validate(); len(errs) > 0 || len(warns) > 0 {
		t.Errorf("errs=%v warns=%v", errs, warns)
	}
}
