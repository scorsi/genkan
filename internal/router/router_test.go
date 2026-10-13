package router

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// echo answers with its name and the forwarding headers it received.
func echo(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s host=%s for=%s proto=%s fhost=%s", name, r.Host,
			r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Forwarded-Proto"), r.Header.Get("X-Forwarded-Host"))
	})
}

func TestRouting(t *testing.T) {
	a := httptest.NewServer(echo("A"))
	defer a.Close()
	b := httptest.NewServer(echo("B"))
	defer b.Close()
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	r := New("lan", log, true)
	r.Handle("a.example", "route-a", Proxy(mustURL(a.URL), log))
	r.Handle("b.example", "route-b", Proxy(mustURL(b.URL), log))
	front := httptest.NewServer(r)
	defer front.Close()

	tests := []struct {
		host, want string
		status     int
	}{
		{"a.example", "A host=a.example", 200},
		{"b.example", "B host=b.example", 200},
		{"A.Example:8443", "A host=A.Example:8443", 200},
		{"c.example", "404 page not found", 404},
	}
	for _, tt := range tests {
		req, _ := http.NewRequest("GET", front.URL+"/p", nil)
		req.Host = tt.host
		req.Header.Set("X-Forwarded-For", "6.6.6.6")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "evil.example")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != tt.status || !strings.HasPrefix(string(body), tt.want) {
			t.Errorf("%s: got %d %q", tt.host, res.StatusCode, body)
		}
		if tt.status == 200 && !strings.HasSuffix(string(body), " for=127.0.0.1 proto=http fhost="+tt.host) {
			t.Errorf("%s: forwarding headers not overwritten: %q", tt.host, body)
		}
	}
	if !strings.Contains(logs.String(), `"route":"route-a"`) || !strings.Contains(logs.String(), `"status":404`) {
		t.Errorf("access log: %s", logs.String())
	}
}

func TestBadBackend(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	r := New("lan", log, false)
	r.Handle("a.example", "a", Proxy(mustURL("http://127.0.0.1:1"), log))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://a.example/", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("got %d, want 502", rec.Code)
	}
}

// A body trickled continuously passes however slow it is; one that stalls is cut (ADR 0007).
func TestProgressDeadline(t *testing.T) {
	ProgressTimeout = 200 * time.Millisecond
	defer func() { ProgressTimeout = 60 * time.Second }()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, n)
	}))
	defer backend.Close()
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	r := New("lan", log, false)
	r.Handle("a.example", "a", Proxy(mustURL(backend.URL), log))
	front := httptest.NewServer(r)
	defer front.Close()

	send := func(pause time.Duration, stallAt int) (string, error) {
		c, err := net.Dial("tcp", front.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(c, "POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 10\r\n\r\n")
		for i := 0; i < 10; i++ {
			if i == stallAt {
				time.Sleep(4 * ProgressTimeout)
			} else {
				time.Sleep(pause)
			}
			if _, err := c.Write([]byte("x")); err != nil {
				break
			}
		}
		res, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return "", err
		}
		body, _ := io.ReadAll(res.Body)
		return string(body), nil
	}
	if body, err := send(50*time.Millisecond, -1); err != nil || body != "10" {
		t.Errorf("slow continuous body: got %q, %v; want 10", body, err)
	}
	if body, err := send(0, 5); err == nil && body == "10" {
		t.Error("stalled body was accepted")
	}
}

func TestStatic(t *testing.T) {
	root := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("index.html", "home")
	write("a.css", "css")
	write("docs/index.html", "docs")
	write("bare/x.txt", "x")
	write("../secret", "secret")
	h := Static(root)

	tests := []struct {
		path, want string
		status     int
	}{
		{"/", "home", 200},
		{"/a.css", "css", 200},
		{"/docs/", "docs", 200},
		{"/docs", "", 301},
		{"/bare/", "404 page not found\n", 404},
		{"/bare", "404 page not found\n", 404},
		{"/bare/x.txt", "x", 200},
		{"/missing", "404 page not found\n", 404},
		{"/missing/", "404 page not found\n", 404},
		{"/../secret", "404 page not found\n", 404},
	}
	for _, tt := range tests {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "http://s.example"+tt.path, nil))
		if rec.Code != tt.status || (tt.want != "" && rec.Body.String() != tt.want) {
			t.Errorf("%s: got %d %q, want %d %q", tt.path, rec.Code, rec.Body, tt.status, tt.want)
		}
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
