package router

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/scorsi/genkan/internal/logging"
	"github.com/scorsi/genkan/internal/metrics"
)

// raw sends one request written by hand, so Host and the request line are exactly as given.
func raw(t *testing.T, addr, request string) *http.Response {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	io.WriteString(c, request)
	method, _, _ := strings.Cut(request, " ")
	res, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestRedirect(t *testing.T) {
	var logs bytes.Buffer
	m := metrics.New("test")
	r := New("http", logging.New(&logs, slog.LevelInfo), true, m)
	r.Default("-", Redirect())
	front := httptest.NewServer(r)
	defer front.Close()
	addr := front.Listener.Addr().String()

	tests := []struct {
		name, request string
		status        int
		location      string
	}{
		{"host", "GET / HTTP/1.1\r\nHost: cv.example.org\r\n\r\n", 301, "https://cv.example.org/"},
		{"port dropped", "GET /a HTTP/1.1\r\nHost: cv.example.org:80\r\n\r\n", 301, "https://cv.example.org/a"},
		{"uppercase host", "GET / HTTP/1.1\r\nHost: CV.Example.org\r\n\r\n", 301, "https://cv.example.org/"},
		{"path and query", "GET /a/b%20c?x=1&y=%2F HTTP/1.1\r\nHost: cv.example.org\r\n\r\n", 301, "https://cv.example.org/a/b%20c?x=1&y=%2F"},
		{"ipv6 with port", "GET /p?q HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n", 301, "https://[2001:db8::1]/p?q"},
		{"ipv6 without port", "GET / HTTP/1.1\r\nHost: [2001:db8::1]\r\n\r\n", 301, "https://[2001:db8::1]/"},
		{"absolute form", "GET http://cv.example.org/x?y HTTP/1.1\r\nHost: cv.example.org\r\n\r\n", 301, "https://cv.example.org/x?y"},
		{"head", "HEAD /h HTTP/1.1\r\nHost: cv.example.org\r\n\r\n", 301, "https://cv.example.org/h"},
		{"post", "POST /f HTTP/1.1\r\nHost: cv.example.org\r\nContent-Length: 2\r\n\r\nab", 301, "https://cv.example.org/f"},
		{"opaque uri", "GET http:x HTTP/1.1\r\nHost: cv.example.org\r\n\r\n", 301, "https://cv.example.org/"},
		{"no host, HTTP/1.0", "GET / HTTP/1.0\r\n\r\n", 400, ""},
		{"port only", "GET / HTTP/1.1\r\nHost: :80\r\n\r\n", 400, ""},
		{"no host, HTTP/1.1", "GET / HTTP/1.1\r\n\r\n", 400, ""}, // net/http's own 400, before routing
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := raw(t, addr, tt.request)
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != tt.status || res.Header.Get("Location") != tt.location {
				t.Errorf("got %d Location %q, want %d %q", res.StatusCode, res.Header.Get("Location"), tt.status, tt.location)
			}
			if strings.HasPrefix(tt.request, "HEAD") && len(body) > 0 {
				t.Errorf("HEAD with a body: %q", body)
			}
		})
	}

	if !strings.Contains(logs.String(), `"event":"request","listener":"http","route":"-","client":"127.0.0.1","method":"GET","host":"cv.example.org","path":"/a/b c","proto":"HTTP/1.1","tls":"-","status":301`) {
		t.Errorf("no request record for the redirect:\n%s", logs.String())
	}
	var out strings.Builder
	m.Write(&out)
	if !strings.Contains(out.String(), `genkan_requests_total{listener="http",route="-",method="GET",code="3xx"}`) {
		t.Errorf("redirect not counted:\n%s", out.String())
	}
}
