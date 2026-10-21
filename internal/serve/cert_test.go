package serve

import (
	"crypto/tls"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/scorsi/genkan/internal/config"
	"github.com/scorsi/genkan/internal/logging"
	"github.com/scorsi/genkan/internal/metrics"
)

// served returns the CommonName of the certificate addr serves for sni, or "" if the handshake fails.
func served(addr, sni string) string {
	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err != nil {
		return ""
	}
	defer c.Close()
	return c.ConnectionState().PeerCertificates[0].Subject.CommonName
}

// G2: a pair hanko has not written yet (missing file) or is writing (key not matching the
// certificate) is not ready: genkan starts without it and serves the other names, a reload
// keeps the pair it already had, and the pair is picked up by the reload that follows its
// completion.
func TestCertificateNotReady(t *testing.T) {
	var logs syncBuffer
	s := New(logging.New(&logs, nil), new(slog.LevelVar), metrics.New("test"))
	defer s.Shutdown(0)
	lan := config.Listener{Name: "lan", Addr: freeAddr(t), Mode: "tls"}
	a, late := certFiles(t, "a.example"), certFiles(t, "late.example")
	lateCert, _ := os.ReadFile(late.Cert)
	lateKey, _ := os.ReadFile(late.Key)
	os.Remove(late.Cert)
	os.Remove(late.Key)
	apply := func() error {
		return s.Apply(&config.Config{
			Log: config.Log{Level: "info"}, Listeners: []config.Listener{lan},
			Certificates: map[string]config.Certificate{"a.example": a, "late.example": late},
			Routes:       []config.Route{route("a", "lan", "a.example", backend(t, "A")), route("late", "lan", "late.example", backend(t, "L"))},
		})
	}

	// Start with late's files missing.
	if err := apply(); err != nil {
		t.Fatalf("start without a pair: %v", err)
	}
	if got := get(lan.Addr, "a.example"); got != "A" {
		t.Errorf("a.example: %q", got)
	}
	if got := served(lan.Addr, "late.example"); got != "" {
		t.Errorf("late.example served %q without a certificate", got)
	}
	if !strings.Contains(logs.String(), `"event":"certificate-not-ready","certificate":"late.example"`) {
		t.Errorf("no certificate-not-ready line: %s", logs.String())
	}

	// Only the certificate written so far: still not ready.
	os.WriteFile(late.Cert, lateCert, 0o600)
	if err := apply(); err != nil || served(lan.Addr, "late.example") != "" {
		t.Errorf("half-written pair: %v, served %q", err, served(lan.Addr, "late.example"))
	}

	// The pair completes: the next reload serves it.
	os.WriteFile(late.Key, lateKey, 0o600)
	if err := apply(); err != nil || served(lan.Addr, "late.example") != "late.example" {
		t.Errorf("completed pair: %v, served %q", err, served(lan.Addr, "late.example"))
	}

	// A renewal caught between its two renames (new certificate, old key): the loaded pair stays.
	other := certFiles(t, "late.example")
	newCert, _ := os.ReadFile(other.Cert)
	os.WriteFile(late.Cert, newCert, 0o600)
	logs.mu.Lock()
	logs.buf.Reset()
	logs.mu.Unlock()
	if err := apply(); err != nil {
		t.Fatalf("mismatched pair failed the reload: %v", err)
	}
	if got := served(lan.Addr, "late.example"); got != "late.example" {
		t.Errorf("mismatched pair: served %q, want the loaded pair", got)
	}
	if !strings.Contains(logs.String(), `"event":"certificate-not-ready","certificate":"late.example"`) {
		t.Errorf("no certificate-not-ready line for the mismatch: %s", logs.String())
	}

	// An unparsable file is not "not ready": it still fails the reload (ADR 0004).
	os.WriteFile(late.Cert, []byte("garbage"), 0o600)
	if err := apply(); err == nil {
		t.Error("reload with an unparsable certificate succeeded")
	}
}
