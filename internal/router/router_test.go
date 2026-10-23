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

	"github.com/scorsi/genkan/internal/logging"
	"github.com/scorsi/genkan/internal/metrics"
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
	log := logging.New(&logs, slog.LevelInfo)
	m := metrics.New("test")
	r := New("lan", log, true, m)
	r.Handle("a.example", "route-a", Proxy(mustURL(a.URL), "lan", "route-a", log, m))
	r.Handle("b.example", "route-b", Proxy(mustURL(b.URL), "lan", "route-b", log, m))
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
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != len(tests) {
		t.Fatalf("want one request line per request, got %q", lines)
	}
	for _, field := range []string{`"event":"request"`, `"listener":"lan"`, `"route":"route-a"`, `"method":"GET"`,
		`"host":"a.example"`, `"path":"/p"`, `"proto":"HTTP/1.1"`, `"tls":"-"`, `"status":200`, `"dur_us":`} {
		if !strings.Contains(lines[0], field) {
			t.Errorf("request line lacks %s: %s", field, lines[0])
		}
	}
	if !strings.Contains(lines[3], `"route":"-"`) || !strings.Contains(lines[3], `"status":404`) {
		t.Errorf("unrouted request line: %s", lines[3])
	}
	var out strings.Builder
	m.Write(&out)
	for _, want := range []string{
		`genkan_requests_total{listener="lan",route="route-a",method="GET",code="2xx"} 2`,
		`genkan_requests_total{listener="lan",route="-",method="GET",code="4xx"} 1`,
		`genkan_request_duration_seconds_count{listener="lan",route="route-b"} 1`,
	} {
		if !strings.Contains(out.String(), want+"\n") {
			t.Errorf("metrics lack %s:\n%s", want, out.String())
		}
	}
}

func TestBadBackend(t *testing.T) {
	var logs bytes.Buffer
	log := logging.New(&logs, slog.LevelInfo)
	m := metrics.New("test")
	r := New("lan", log, false, m)
	r.Handle("a.example", "a", Proxy(mustURL("http://127.0.0.1:1"), "lan", "a", log, m))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://a.example/", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("got %d, want 502", rec.Code)
	}
	if l := logs.String(); !strings.Contains(l, `"level":"warn","v":1,"event":"upstream-error","listener":"lan","route":"a","err":"dial tcp 127.0.0.1:1:`) {
		t.Errorf("upstream-error line: %s", l)
	}
	var out strings.Builder
	m.Write(&out)
	if !strings.Contains(out.String(), "genkan_upstream_errors_total{route=\"a\"} 1\n") {
		t.Errorf("upstream error not counted:\n%s", out.String())
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
	m := metrics.New("test")
	r := New("lan", log, false, m)
	r.Handle("a.example", "a", Proxy(mustURL(backend.URL), "lan", "a", log, m))
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

// A quiet path is not logged when it succeeds (ADR 0011), still logged when it fails, and still
// counted; other paths of the route are logged as usual.
func TestQuietPaths(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Fail") != "" {
			w.WriteHeader(http.StatusInternalServerError)
		}
		fmt.Fprint(w, "{}")
	}))
	defer backend.Close()
	var logs bytes.Buffer
	log := logging.New(&logs, slog.LevelInfo)
	m := metrics.New("test")
	r := New("lan", log, true, m)
	r.Handle("a.example", "a", Proxy(mustURL(backend.URL), "lan", "a", log, m), "/poll")
	r.Handle("b.example", "b", Proxy(mustURL("http://127.0.0.1:1"), "lan", "b", log, m), "/poll")

	tests := []struct {
		host, path string
		fail       bool
		status     int
		logged     bool
	}{
		{"a.example", "/poll?x=1", false, 200, false},
		{"a.example", "/poll", true, 500, true},
		{"a.example", "/other", false, 200, true},
		{"a.example", "/poll/", false, 200, true},
		{"b.example", "/poll", false, 502, true}, // upstream error
	}
	for _, tt := range tests {
		logs.Reset()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "http://"+tt.host+tt.path, nil)
		if tt.fail {
			req.Header.Set("Fail", "1")
		}
		r.ServeHTTP(rec, req)
		logged := strings.Contains(logs.String(), `"event":"request"`)
		if rec.Code != tt.status || logged != tt.logged {
			t.Errorf("%s%s: got %d logged=%v, want %d logged=%v: %s", tt.host, tt.path, rec.Code, logged, tt.status, tt.logged, logs.String())
		}
	}
	var out strings.Builder
	m.Write(&out)
	for _, want := range []string{
		`genkan_requests_total{listener="lan",route="a",method="POST",code="2xx"} 3`,
		`genkan_requests_total{listener="lan",route="a",method="POST",code="5xx"} 1`,
	} {
		if !strings.Contains(out.String(), want+"\n") {
			t.Errorf("metrics lack %s:\n%s", want, out.String())
		}
	}
}

// A response that fails mid-body (ReverseProxy panics with http.ErrAbortHandler) on a quiet path
// is still logged, though its status was 200.
func TestQuietPathAbort(t *testing.T) {
	var logs bytes.Buffer
	r := New("lan", logging.New(&logs, slog.LevelInfo), true, metrics.New("test"))
	r.Handle("a.example", "a", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("partial"))
		panic(http.ErrAbortHandler)
	}), "/poll")
	func() {
		defer func() { recover() }()
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://a.example/poll", nil))
	}()
	if !strings.Contains(logs.String(), `"event":"request"`) {
		t.Error("aborted quiet request not logged")
	}
}
