// Package config parses and validates the genkan TOML file (ADR 0002, docs/config.md).
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	Log          Log                    `toml:"log"`
	Metrics      Metrics                `toml:"metrics"`
	Listeners    []Listener             `toml:"listeners"`
	Certificates map[string]Certificate `toml:"certificates"`
	Routes       []Route                `toml:"routes"`
}

type Log struct {
	Level  string `toml:"level"`
	Access bool   `toml:"access"`
}

// Metrics is the loopback /metrics listener (ADR 0008); an empty Listen disables it.
type Metrics struct {
	Listen string `toml:"listen"`
}

type Listener struct {
	Name           string   `toml:"name"`
	Addr           string   `toml:"addr"`
	Mode           string   `toml:"mode"`
	AcceptProxy    string   `toml:"accept_proxy"`
	TrustedSources []string `toml:"trusted_sources"`
}

type Certificate struct {
	Cert string `toml:"cert"`
	Key  string `toml:"key"`
}

type Route struct {
	Name        string   `toml:"name"`
	Type        string   `toml:"type"`
	Listeners   []string `toml:"listeners"`
	Hosts       []string `toml:"hosts"`
	Certificate string   `toml:"certificate"`
	Backend     string   `toml:"backend"`
	Root        string   `toml:"root"`
	SNI         []string `toml:"sni"`
	SendProxy   string   `toml:"send_proxy"`
	QuietPaths  []string `toml:"quiet_paths"`
}

// Parse decodes TOML. Unknown keys are errors, one per key.
func Parse(r io.Reader) (*Config, error) {
	c := &Config{Log: Log{Level: "info", Access: true}}
	dec := toml.NewDecoder(r)
	dec.DisallowUnknownFields()
	err := dec.Decode(c)
	var strict *toml.StrictMissingError
	if errors.As(err, &strict) {
		var errs []error
		for i := range strict.Errors {
			row, _ := strict.Errors[i].Position()
			errs = append(errs, fmt.Errorf("line %d: unknown key %q", row, strings.Join(strict.Errors[i].Key(), ".")))
		}
		return nil, errors.Join(errs...)
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Load reads, parses and validates path. The error joins every problem found.
func Load(path string) (*Config, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	c, err := Parse(f)
	if err != nil {
		return nil, nil, err
	}
	errs, warnings := c.Validate()
	if len(errs) > 0 {
		return nil, warnings, errors.Join(errs...)
	}
	return c, warnings, nil
}

// Validate checks the rules of docs/config.md and returns every violation plus the warnings.
func (c *Config) Validate() (errs []error, warnings []string) {
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		bad("log.level: must be debug, info, warn or error, got %q", c.Log.Level)
	}

	if c.Metrics.Listen != "" {
		host, port, err := net.SplitHostPort(c.Metrics.Listen)
		if err != nil || port == "" || (host != "127.0.0.1" && host != "::1") {
			bad("metrics.listen: must be 127.0.0.1:<port> or [::1]:<port>, got %q", c.Metrics.Listen)
		}
	}

	if len(c.Listeners) == 0 {
		bad("no listeners")
	}
	listeners := map[string]*Listener{}
	addrs := map[string]string{}
	for i := range c.Listeners {
		l := &c.Listeners[i]
		where := fmt.Sprintf("listener %q", l.Name)
		if l.Name == "" {
			bad("listeners[%d]: name is required", i)
		} else if _, dup := listeners[l.Name]; dup {
			bad("%s: duplicate name", where)
		}
		listeners[l.Name] = l
		if _, _, err := net.SplitHostPort(l.Addr); err != nil {
			bad("%s: addr %q is not host:port", where, l.Addr)
		} else if other, dup := addrs[l.Addr]; dup {
			bad("%s: addr %q already used by listener %q", where, l.Addr, other)
		} else {
			addrs[l.Addr] = l.Name
		}
		switch l.Mode {
		case "tls", "tcp":
		case "http":
			bad("%s: mode \"http\" not implemented before v1", where)
		default:
			bad("%s: mode must be tls, tcp or http, got %q", where, l.Mode)
		}
		if l.AcceptProxy != "" {
			if l.AcceptProxy != "required" {
				bad("%s: accept_proxy must be \"required\", got %q", where, l.AcceptProxy)
			}
			if l.Mode == "http" {
				bad("%s: accept_proxy on an http listener", where)
			}
			if len(l.TrustedSources) == 0 {
				bad("%s: accept_proxy needs a non-empty trusted_sources", where)
			}
			bad("%s: accept_proxy not implemented before v1", where)
		} else if len(l.TrustedSources) > 0 {
			bad("%s: trusted_sources without accept_proxy", where)
		}
		for _, s := range l.TrustedSources {
			if _, _, err := net.ParseCIDR(s); err != nil {
				bad("%s: trusted_sources %q is not a CIDR", where, s)
			}
		}
	}

	for _, name := range slices.Sorted(maps(c.Certificates)) {
		if c.Certificates[name].Cert == "" {
			bad("certificates.%s: cert is required", name)
		}
		if c.Certificates[name].Key == "" {
			bad("certificates.%s: key is required", name)
		}
	}

	routes := map[string]bool{}
	used := map[string]bool{}
	claimed := map[string]map[string]string{} // listener → host or SNI → route
	tcpRoutes := map[string]int{}
	claim := func(route, listener, host string) {
		if claimed[listener] == nil {
			claimed[listener] = map[string]string{}
		}
		if other, dup := claimed[listener][host]; dup {
			bad("route %q: %q on listener %q already claimed by route %q", route, host, listener, other)
		}
		claimed[listener][host] = route
	}
	for i := range c.Routes {
		r := &c.Routes[i]
		where := fmt.Sprintf("route %q", r.Name)
		if r.Name == "" {
			bad("routes[%d]: name is required", i)
		} else if routes[r.Name] {
			bad("%s: duplicate name", where)
		}
		routes[r.Name] = true
		if len(r.Listeners) == 0 {
			bad("%s: listeners must be non-empty", where)
		}
		allTLS := true
		for _, ln := range r.Listeners {
			l, ok := listeners[ln]
			if !ok {
				bad("%s: unknown listener %q", where, ln)
				continue
			}
			switch l.Mode {
			case "http":
				bad("%s: routes cannot reference http listener %q", where, ln)
			case "tcp":
				allTLS = false
				tcpRoutes[ln]++
				if r.Type != "tcp" {
					bad("%s: listener %q is tcp, only tcp routes may use it", where, ln)
				} else if len(r.SNI) > 0 {
					bad("%s: sni is forbidden on tcp listener %q", where, ln)
				}
			}
		}
		names := r.Hosts
		switch r.Type {
		case "http", "static":
			if len(r.Hosts) == 0 {
				bad("%s: hosts must be non-empty", where)
			}
			for _, h := range r.Hosts {
				if err := checkHost(h); err != nil {
					bad("%s: host %q %s", where, h, err)
				}
			}
			if r.Certificate == "" {
				bad("%s: certificate is required", where)
			} else if _, ok := c.Certificates[r.Certificate]; !ok {
				bad("%s: unknown certificate %q", where, r.Certificate)
			}
			used[r.Certificate] = true
			if len(r.SNI) > 0 {
				bad("%s: sni is only for tcp routes", where)
			}
			if r.SendProxy != "" {
				bad("%s: send_proxy is only for tcp routes", where)
			}
			quiet := map[string]bool{}
			for _, p := range r.QuietPaths {
				switch {
				case !strings.HasPrefix(p, "/"):
					bad("%s: quiet_paths %q must start with /", where, p)
				case strings.ContainsAny(p, "?#"):
					bad("%s: quiet_paths %q must be a path, without query or fragment", where, p)
				case quiet[p]:
					bad("%s: quiet_paths %q listed twice", where, p)
				}
				quiet[p] = true
			}
			if r.Type == "http" {
				if err := checkBackendURL(r.Backend); err != nil {
					bad("%s: backend %q %s", where, r.Backend, err)
				}
				if r.Root != "" {
					bad("%s: root is only for static routes", where)
				}
			} else {
				if !filepath.IsAbs(r.Root) {
					bad("%s: root %q must be an absolute path", where, r.Root)
				}
				if r.Backend != "" {
					bad("%s: backend is only for http and tcp routes", where)
				}
			}
		case "tcp":
			names = r.SNI
			if allTLS && len(r.SNI) == 0 {
				bad("%s: sni is required on tls listeners", where)
			}
			if _, _, err := net.SplitHostPort(r.Backend); err != nil {
				bad("%s: backend %q is not host:port", where, r.Backend)
			}
			if r.SendProxy != "" && r.SendProxy != "v2" {
				bad("%s: send_proxy must be \"v2\", got %q", where, r.SendProxy)
			}
			if len(r.Hosts) > 0 || r.Certificate != "" || r.Root != "" || len(r.QuietPaths) > 0 {
				bad("%s: hosts, certificate, root and quiet_paths are only for http and static routes", where)
			}
			bad("%s: tcp routes not implemented before v1", where)
		default:
			bad("%s: type must be http, static or tcp, got %q", where, r.Type)
		}
		for _, ln := range r.Listeners {
			for _, h := range names {
				claim(r.Name, ln, h)
			}
		}
	}
	for _, name := range slices.Sorted(maps(listeners)) {
		if listeners[name].Mode == "tcp" && tcpRoutes[name] != 1 {
			bad("listener %q: tcp mode needs exactly one route, has %d", name, tcpRoutes[name])
		}
	}
	for _, name := range slices.Sorted(maps(c.Certificates)) {
		if !used[name] {
			warnings = append(warnings, fmt.Sprintf("certificates.%s: declared but never referenced", name))
		}
	}
	return errs, warnings
}

func maps[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func checkHost(h string) error {
	switch {
	case h == "":
		return errors.New("is empty")
	case strings.Contains(h, "*"):
		return errors.New("wildcards not implemented before v1.2")
	case strings.Contains(h, ":"):
		return errors.New("must not include a port")
	case h != strings.ToLower(h):
		return errors.New("must be lowercase")
	}
	return nil
}

func checkBackendURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return errors.New("is not a URL")
	}
	switch {
	case u.Scheme != "http":
		return errors.New("must be an http:// URL")
	case u.Host == "":
		return errors.New("has no host")
	case u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "":
		return errors.New("must be http://host:port with no path, query or userinfo")
	}
	return nil
}
