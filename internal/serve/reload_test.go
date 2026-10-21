package serve

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scorsi/genkan/internal/config"
	"github.com/scorsi/genkan/internal/metrics"
)

// certFiles writes a self-signed pair for host and returns its config entry.
func certFiles(t *testing.T, host string) config.Certificate {
	t.Helper()
	c := selfSigned(t, host)
	key, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cf := config.Certificate{Cert: filepath.Join(dir, "cert.pem"), Key: filepath.Join(dir, "key.pem")}
	os.WriteFile(cf.Cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]}), 0o600)
	os.WriteFile(cf.Key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600)
	return cf
}

func backend(t *testing.T, body string) string {
	t.Helper()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, body) }))
	t.Cleanup(b.Close)
	return b.URL
}

// get requests https://host/ through addr and returns the body, or "" if the handshake or request failed.
func get(addr, host string) string {
	c := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{ServerName: host, InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}}
	req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	req.Host = host
	resp, err := c.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func route(name, listener, host, backend string) config.Route {
	return config.Route{Name: name, Type: "http", Listeners: []string{listener}, Hosts: []string{host}, Certificate: host, Backend: backend}
}

func TestReload(t *testing.T) {
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), new(slog.LevelVar), metrics.New("test"))
	defer s.Shutdown(0)
	certs := map[string]config.Certificate{"a.example": certFiles(t, "a.example"), "b.example": certFiles(t, "b.example")}
	a, b := backend(t, "A"), backend(t, "B")
	lan := config.Listener{Name: "lan", Addr: freeAddr(t), Mode: "tls"}
	extra := config.Listener{Name: "extra", Addr: freeAddr(t), Mode: "tls"}

	// One listener serving a.example.
	if err := s.Apply(&config.Config{
		Log: config.Log{Level: "info"}, Listeners: []config.Listener{lan}, Certificates: certs,
		Routes: []config.Route{route("a", "lan", "a.example", a)},
	}); err != nil {
		t.Fatal(err)
	}
	if got := get(lan.Addr, "a.example"); got != "A" {
		t.Fatalf("a.example before reload: %q", got)
	}

	// a.example removed, b.example added, a second listener bound: same socket for lan.
	if err := s.Apply(&config.Config{
		Log: config.Log{Level: "debug"}, Listeners: []config.Listener{lan, extra}, Certificates: certs,
		Routes: []config.Route{route("b", "lan", "b.example", b), route("b-extra", "extra", "a.example", a)},
	}); err != nil {
		t.Fatal(err)
	}
	if got := get(lan.Addr, "a.example"); got != "" {
		t.Errorf("a.example after removal: %q, want handshake failure", got)
	}
	if got := get(lan.Addr, "b.example"); got != "B" {
		t.Errorf("b.example after reload: %q", got)
	}
	if got := get(extra.Addr, "a.example"); got != "A" {
		t.Errorf("new listener: %q", got)
	}
	if s.level.Level() != slog.LevelDebug {
		t.Errorf("log level not reloaded: %v", s.level.Level())
	}
	running := s.slots[lan.Addr].state.Load()

	// Failed reloads: unparsable certificate file (a missing one is "not ready", TestCertificateNotReady),
	// then an address already in use.
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	os.WriteFile(garbage, []byte("garbage"), 0o600)
	unparsable := map[string]config.Certificate{"b.example": {Cert: garbage, Key: garbage}}
	if err := s.Apply(&config.Config{
		Log: config.Log{Level: "info"}, Listeners: []config.Listener{lan}, Certificates: unparsable,
		Routes: []config.Route{route("b", "lan", "b.example", b)},
	}); err == nil {
		t.Error("reload with an unparsable certificate succeeded")
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	third := freeAddr(t)
	if err := s.Apply(&config.Config{
		Log: config.Log{Level: "info"}, Certificates: certs,
		Listeners: []config.Listener{lan, {Name: "third", Addr: third, Mode: "tls"}, {Name: "busy", Addr: busy.Addr().String(), Mode: "tls"}},
		Routes:    []config.Route{route("b", "lan", "b.example", b)},
	}); err == nil {
		t.Error("reload onto a busy address succeeded")
	}
	if s.slots[lan.Addr].state.Load() != running || get(lan.Addr, "b.example") != "B" || get(extra.Addr, "a.example") != "A" {
		t.Error("failed reload changed the running config")
	}
	if c, err := net.Dial("tcp", third); err == nil {
		c.Close()
		t.Error("failed reload left a fresh socket bound")
	}

	// extra dropped: its socket closes.
	if err := s.Apply(&config.Config{
		Log: config.Log{Level: "info"}, Listeners: []config.Listener{lan}, Certificates: certs,
		Routes: []config.Route{route("b", "lan", "b.example", b)},
	}); err != nil {
		t.Fatal(err)
	}
	if c, err := net.Dial("tcp", extra.Addr); err == nil {
		c.Close()
		t.Error("removed listener still accepts connections")
	}
	if got := get(lan.Addr, "b.example"); got != "B" {
		t.Errorf("b.example after dropping extra: %q", got)
	}
}

func TestNotify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	sock, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if err := notify("READY=1"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _ := sock.Read(buf)
	if string(buf[:n]) != "READY=1" {
		t.Errorf("got %q", buf[:n])
	}
	t.Setenv("NOTIFY_SOCKET", "")
	if err := notify("READY=1"); err != nil {
		t.Errorf("without NOTIFY_SOCKET: %v", err)
	}
}

// G4: a TLS session resumed after a reload is checked against the current state: a removed name
// does not resume, and a rotated certificate is the one served.
func TestResumptionAfterReload(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, h2 := range []bool{false, true} {
			t.Run(fmt.Sprintf("TLS%x/h2=%t", version, h2), func(t *testing.T) {
				s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), new(slog.LevelVar), metrics.New("test"))
				defer s.Shutdown(0)
				lan := config.Listener{Name: "lan", Addr: freeAddr(t), Mode: "tls"}
				a, b := backend(t, "A"), backend(t, "B")
				apply := func(certs map[string]config.Certificate, routes ...config.Route) {
					t.Helper()
					if err := s.Apply(&config.Config{Log: config.Log{Level: "info"}, Listeners: []config.Listener{lan}, Certificates: certs, Routes: routes}); err != nil {
						t.Fatal(err)
					}
				}
				cache := tls.NewLRUClientSessionCache(8)
				// dial reads the response and session ticket on a fresh connection; nil if TLS fails.
				dial := func(sni string) *tls.ConnectionState {
					tr := &http.Transport{
						TLSClientConfig:   &tls.Config{ServerName: sni, InsecureSkipVerify: true, ClientSessionCache: cache, MinVersion: version, MaxVersion: version},
						ForceAttemptHTTP2: h2,
						DisableKeepAlives: true,
					}
					defer tr.CloseIdleConnections()
					req, _ := http.NewRequest("GET", "https://"+lan.Addr+"/", nil)
					req.Host = sni
					resp, err := (&http.Client{Transport: tr}).Do(req)
					if err != nil {
						return nil
					}
					defer resp.Body.Close()
					if _, err := io.Copy(io.Discard, resp.Body); err != nil {
						t.Fatal(err)
					}
					if h2 && (resp.ProtoMajor != 2 || resp.TLS.NegotiatedProtocol != "h2") {
						t.Fatalf("HTTP/2 not negotiated: %s, %s", resp.Proto, resp.TLS.NegotiatedProtocol)
					}
					return resp.TLS
				}

				certA := map[string]config.Certificate{"a.example": certFiles(t, "a.example"), "b.example": certFiles(t, "b.example")}
				apply(certA, route("a", "lan", "a.example", a), route("b", "lan", "b.example", b))
				if dial("a.example") == nil {
					t.Fatal("first handshake failed")
				}

				if cs := dial("a.example"); cs == nil || !cs.DidResume {
					t.Fatal("session not resumed without a reload: the test proves nothing")
				}

				// Re-reading the same files must preserve resumption, even if another name changes.
				apply(certA, route("a", "lan", "a.example", a), route("b", "lan", "b.example", b))
				if cs := dial("a.example"); cs == nil || !cs.DidResume {
					t.Fatal("unchanged certificate did not resume after reload")
				}
				other := map[string]config.Certificate{"a.example": certA["a.example"], "b.example": certFiles(t, "b.example")}
				apply(other, route("a", "lan", "a.example", a), route("b", "lan", "b.example", b))
				if cs := dial("a.example"); cs == nil || !cs.DidResume {
					t.Fatal("another name's certificate rotation invalidated this session")
				}

				// a.example removed: its cached session must not reach the listener.
				apply(certA, route("b", "lan", "b.example", b))
				if cs := dial("a.example"); cs != nil {
					t.Errorf("removed name resumed=%v", cs.DidResume)
				}

				// a.example back with a rotated certificate: the resumed session must not keep the old one.
				apply(certA, route("a", "lan", "a.example", a))
				dial("a.example")
				rotated := map[string]config.Certificate{"a.example": certFiles(t, "a.example"), "b.example": certA["b.example"]}
				want, _ := os.ReadFile(rotated["a.example"].Cert)
				apply(rotated, route("a", "lan", "a.example", a))
				cs := dial("a.example")
				if cs == nil || cs.DidResume || !strings.Contains(string(want), pemBody(cs.PeerCertificates[0].Raw)) {
					t.Errorf("after rotation: %v, want a full handshake with the new certificate", cs)
				}
			})
		}
	}
}

// pemBody is the base64 body of der as PEM writes it, first line only.
func pemBody(der []byte) string {
	return strings.Split(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "\n")[1]
}
