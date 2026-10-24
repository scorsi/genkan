package serve

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/scorsi/genkan/internal/config"
)

// An http listener redirects, and a reload switches its address between http and tls without
// rebinding.
func TestHTTPListener(t *testing.T) {
	addr := freeAddr(t)
	plain := &config.Config{Listeners: []config.Listener{{Name: "redirect", Addr: addr, Mode: "http"}}}
	s, logs, _ := newTestServer(t, plain)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	redirect := func() string {
		res, err := client.Get("http://" + addr + "/p?q=1")
		if err != nil {
			return err.Error()
		}
		res.Body.Close()
		return res.Status + " " + res.Header.Get("Location")
	}
	if got, want := redirect(), "301 Moved Permanently https://127.0.0.1/p?q=1"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if !strings.Contains(logs.String(), `"event":"request","listener":"redirect","route":"-"`) {
		t.Errorf("redirect not logged:\n%s", logs)
	}

	// A keep-alive connection opened before the reload.
	kept, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer kept.Close()
	br := bufio.NewReader(kept)
	ask := func() int {
		io.WriteString(kept, "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
		res, err := http.ReadResponse(br, nil)
		if err != nil {
			return 0
		}
		io.Copy(io.Discard, res.Body)
		return res.StatusCode
	}
	if got := ask(); got != 301 {
		t.Fatalf("kept connection: %d", got)
	}

	tls := &config.Config{
		Log:          plain.Log,
		Listeners:    []config.Listener{{Name: "redirect", Addr: addr, Mode: "tls"}},
		Certificates: map[string]config.Certificate{"a.example": certFiles(t, "a.example")},
		Routes:       []config.Route{route("a", "redirect", "a.example", backend(t, "A"))},
	}
	if err := s.Apply(tls); err != nil {
		t.Fatal(err)
	}
	if got := get(addr, "a.example"); got != "A" {
		t.Errorf("after reload to tls: %q", got)
	}
	if got := ask(); got != http.StatusMisdirectedRequest {
		t.Errorf("plaintext request on a listener now tls: %d, want 421", got)
	}
	if err := s.Apply(plain); err != nil {
		t.Fatal(err)
	}
	if got := redirect(); !strings.HasPrefix(got, "301 ") {
		t.Errorf("after reload back to http: %q", got)
	}
}
