package router

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scorsi/genkan/internal/logging"
	"github.com/scorsi/genkan/internal/metrics"
)

// shortTimeout shrinks ProgressTimeout for one test: 150 ms against transfers that last 600 ms.
func shortTimeout(t *testing.T) {
	ProgressTimeout = 150 * time.Millisecond
	t.Cleanup(func() { ProgressTimeout = 60 * time.Second })
}

// proxied serves a.example through a Router to a backend running h, over HTTP/1.1 or, with h2,
// over TLS with HTTP/2. The backend's handlers end when the test does.
func proxied(t *testing.T, h http.HandlerFunc, h2 bool) (front *httptest.Server, logs *syncBuffer, m *metrics.Registry) {
	t.Helper()
	backend := httptest.NewServer(h)
	t.Cleanup(backend.Close)
	logs = &syncBuffer{}
	log := logging.New(logs, nil)
	m = metrics.New("test")
	r := New("lan", log, true, m)
	r.Handle("a.example", "a", Proxy(mustURL(backend.URL), "lan", "a", log, m))
	front = httptest.NewUnstartedServer(r)
	if h2 {
		front.EnableHTTP2 = true
		front.StartTLS()
	} else {
		front.Start()
	}
	t.Cleanup(front.Close)
	return front, logs, m
}

func do(t *testing.T, front *httptest.Server, method string, body io.Reader) (string, error) {
	t.Helper()
	req, _ := http.NewRequest(method, front.URL+"/", body)
	req.Host = "a.example"
	res, err := front.Client().Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return string(b), err
}

// G1: a download sending 8 KiB every 30 ms outlasts the timeout and completes.
func TestContinuousDownload(t *testing.T) {
	shortTimeout(t)
	front, _, _ := proxied(t, func(w http.ResponseWriter, r *http.Request) {
		for range 20 {
			w.Write(make([]byte, 8192))
			w.(http.Flusher).Flush()
			time.Sleep(30 * time.Millisecond)
		}
	}, false)
	body, err := do(t, front, "GET", nil)
	if err != nil || len(body) != 20*8192 {
		t.Errorf("got %d bytes, %v; want %d", len(body), err, 20*8192)
	}
}

// G1: an HTTP/2 upload sending a byte every 30 ms outlasts the timeout and completes.
func TestH2ContinuousUpload(t *testing.T) {
	shortTimeout(t)
	front, _, _ := proxied(t, func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, n)
	}, true)
	pr, pw := io.Pipe()
	go func() {
		for range 20 {
			time.Sleep(30 * time.Millisecond)
			pw.Write([]byte("x"))
		}
		pw.Close()
	}()
	if body, err := do(t, front, "POST", pr); err != nil || body != "20" {
		t.Errorf("got %q, %v; want 20", body, err)
	}
}

// G1: the wait for the backend's headers is not bounded (ADR 0007: git pack processing).
func TestSlowBackendHeaders(t *testing.T) {
	shortTimeout(t)
	for _, h2 := range []bool{false, true} {
		front, _, _ := proxied(t, func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(4 * ProgressTimeout)
			io.WriteString(w, "late")
		}, h2)
		if body, err := do(t, front, "GET", nil); err != nil || body != "late" {
			t.Errorf("h2=%v: got %q, %v; want late", h2, body, err)
		}
	}
}

// G1: a client that never reads the response is still cut, and the request is logged.
func TestStalledClientRead(t *testing.T) {
	shortTimeout(t)
	done := make(chan struct{}) // closed before the servers, so blocked handlers return
	defer close(done)
	front, logs, _ := proxied(t, func(w http.ResponseWriter, r *http.Request) {
		for {
			select {
			case <-done:
				return
			case <-r.Context().Done():
				return
			default:
			}
			if _, err := w.Write(make([]byte, 8192)); err != nil {
				return
			}
		}
	}, false)
	c, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
	if !waitFor(logs, `"event":"request"`) {
		t.Error("response to a client that does not read was never cut")
	}
}

// G3: a backend that stops sending its body mid-response is cut, even when HTTP/1.1's background
// read is not waiting on the socket (it consumed the first byte of a pipelined request).
func TestStalledUpstreamBody(t *testing.T) {
	shortTimeout(t)
	done := make(chan struct{}) // closed before the servers, so blocked handlers return
	defer close(done)
	front, _, _ := proxied(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 8192))
		w.(http.Flusher).Flush()
		select {
		case <-done:
		case <-r.Context().Done():
		}
	}, false)
	c, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * ProgressTimeout))
	fmt.Fprint(c, "POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 1\r\n\r\nx")
	time.Sleep(ProgressTimeout / 3)
	fmt.Fprint(c, "G")
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(res.Body)
	if ne, ok := err.(net.Error); err == nil || ok && ne.Timeout() {
		t.Errorf("stalled backend body: %v, want the response aborted by genkan", err)
	}
}

// G3: a backend that stops reading an upload is cut: 502 instead of a request held forever.
func TestStalledUpstreamWrite(t *testing.T) {
	shortTimeout(t)
	done := make(chan struct{}) // closed before the servers, so blocked handlers return
	defer close(done)
	front, _, _ := proxied(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-done:
		case <-r.Context().Done():
		}
	}, false)
	c, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(40 * ProgressTimeout))
	const size = 64 << 20
	fmt.Fprintf(c, "POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: %d\r\n\r\n", size)
	go func() {
		chunk := make([]byte, 64<<10)
		for sent := 0; sent < size; sent += len(chunk) {
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
	}()
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || res.StatusCode != http.StatusBadGateway {
		t.Errorf("backend not reading the upload: %v, %v; want 502", res, err)
	}
}

// G5: a response aborted mid-body (ReverseProxy panics with http.ErrAbortHandler) is still
// logged and counted, with the status and the bytes actually sent.
func TestAbortedResponseLogged(t *testing.T) {
	front, logs, m := proxied(t, func(w http.ResponseWriter, r *http.Request) {
		c, buf, _ := http.NewResponseController(w).Hijack()
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx")
		buf.Flush()
		c.Close()
	}, false)
	if _, err := do(t, front, "GET", nil); err == nil {
		t.Fatal("truncated response read without error")
	}
	if !waitFor(logs, `"event":"request"`) {
		t.Fatalf("no request line: %s", logs.String())
	}
	for _, field := range []string{`"route":"a"`, `"status":200`, `"bytes":1`} {
		if !strings.Contains(logs.String(), field) {
			t.Errorf("request line lacks %s: %s", field, logs.String())
		}
	}
	var out strings.Builder
	m.Write(&out)
	if !strings.Contains(out.String(), `genkan_requests_total{listener="lan",route="a",method="GET",code="2xx"} 1`+"\n") {
		t.Errorf("aborted request not counted:\n%s", out.String())
	}
}

func waitFor(logs *syncBuffer, s string) bool {
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if strings.Contains(logs.String(), s) {
			return true
		}
	}
	return false
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
