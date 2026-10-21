package serve

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scorsi/genkan/internal/config"
	"github.com/scorsi/genkan/internal/logging"
	"github.com/scorsi/genkan/internal/metrics"
	"github.com/scorsi/genkan/internal/router"
)

// G6: a loopback scraper that stops reading cannot retain a response writer indefinitely.
func TestMetricsWriteDeadline(t *testing.T) {
	old := router.ProgressTimeout
	router.ProgressTimeout = 150 * time.Millisecond
	defer func() { router.ProgressTimeout = old }()
	// Force exposition beyond the socket buffers without thousands of metric series.
	m := metrics.New(strings.Repeat("v", 16<<20))
	addr := freeAddr(t)
	stop, err := serveMetrics(addr, logging.New(io.Discard, nil), m)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(c, "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	time.Sleep(4 * router.ProgressTimeout)
	_, err = io.Copy(io.Discard, res.Body)
	if ne, ok := err.(net.Error); err == nil || ok && ne.Timeout() {
		t.Fatalf("stalled scrape: %v, want the response aborted by genkan", err)
	}
}

// A failed handshake becomes a tls-handshake-error schema line and is counted on its listener;
// the loaded certificate's expiry is exported.
func TestHandshakeErrorAndExpiry(t *testing.T) {
	var logs syncBuffer
	m := metrics.New("test")
	s := New(logging.New(&logs, slog.LevelInfo), new(slog.LevelVar), m)
	defer s.Shutdown(0)
	lan := config.Listener{Name: "lan", Addr: freeAddr(t), Mode: "tls"}
	if err := s.Apply(&config.Config{
		Log: config.Log{Level: "info"}, Listeners: []config.Listener{lan},
		Certificates: map[string]config.Certificate{"a.example": certFiles(t, "a.example")},
		Routes:       []config.Route{route("a", "lan", "a.example", backend(t, "A"))},
	}); err != nil {
		t.Fatal(err)
	}
	if got := get(lan.Addr, "unknown.example"); got != "" {
		t.Fatalf("unknown SNI served %q", got)
	}
	var out strings.Builder
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		out.Reset()
		m.Write(&out)
		if strings.Contains(out.String(), `genkan_tls_handshake_errors_total{listener="lan"} 1`) {
			break
		}
	}
	if !strings.Contains(out.String(), `genkan_tls_handshake_errors_total{listener="lan"} 1`+"\n") {
		t.Errorf("handshake error not counted:\n%s", out.String())
	}
	if !strings.Contains(out.String(), `genkan_certificate_expiry_timestamp_seconds{certificate="a.example"} `) {
		t.Errorf("no certificate expiry:\n%s", out.String())
	}
	if !strings.Contains(logs.String(), `"level":"warn","v":1,"event":"tls-handshake-error","err":"http: TLS handshake error from 127.0.0.1:`) {
		t.Errorf("handshake error line: %s", logs.String())
	}
}

// syncBuffer is written by the server's goroutines while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
