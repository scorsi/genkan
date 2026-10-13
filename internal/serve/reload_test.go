package serve

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/scorsi/genkan/internal/config"
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
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), new(slog.LevelVar))
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

	// Failed reloads: missing certificate file, then an address already in use.
	missing := map[string]config.Certificate{"b.example": {Cert: "/nonexistent", Key: "/nonexistent"}}
	if err := s.Apply(&config.Config{
		Log: config.Log{Level: "info"}, Listeners: []config.Listener{lan}, Certificates: missing,
		Routes: []config.Route{route("b", "lan", "b.example", b)},
	}); err == nil {
		t.Error("reload with a missing certificate succeeded")
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
