package serve

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scorsi/genkan/internal/config"
	"github.com/scorsi/genkan/internal/router"
)

// ADR 0016: gRPC through a TLS listener to a backend speaking HTTP/1.1 and h2c prior knowledge on
// one port. gRPC framing is hand-rolled: a compression flag, a 4-byte length, the message; the
// call's status lives in the trailers.

func grpcFrame(msg []byte) []byte {
	b := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(b[1:], uint32(len(msg)))
	return append(b, msg...)
}

func readFrame(r io.Reader) ([]byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint32(head[1:]))
	_, err := io.ReadFull(r, msg)
	return msg, err
}

// grpcStatus writes the trailers a gRPC server ends a call with, undeclared as gRPC servers do.
func grpcStatus(w http.ResponseWriter, code, msg string) {
	w.Header().Set(http.TrailerPrefix+"Grpc-Status", code)
	w.Header().Set(http.TrailerPrefix+"Grpc-Message", msg)
	w.Header().Set(http.TrailerPrefix+"Grpc-Status-Details-Bin", "CAMSBGRldGFpbA")
}

// forgeBackend serves h on one plaintext port, HTTP/1.1 and h2c prior knowledge (hyper's auto
// builder in the forge).
func forgeBackend(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	b := httptest.NewUnstartedServer(h)
	b.Config.Protocols = new(http.Protocols)
	b.Config.Protocols.SetHTTP1(true)
	b.Config.Protocols.SetUnencryptedHTTP2(true)
	b.Start()
	t.Cleanup(b.Close)
	return b.URL
}

// grpcGenkan serves two h2c routes to backend on a TLS listener: grpc.example with progress_timeout
// raised, plain.example with the default. ProgressTimeout shrinks to 100 ms for the test.
func grpcGenkan(t *testing.T, backend, raised string) (addr string, logs *syncBuffer) {
	t.Helper()
	router.ProgressTimeout = 100 * time.Millisecond
	t.Cleanup(func() { router.ProgressTimeout = 60 * time.Second })
	addr = freeAddr(t)
	grpc := route("grpc", "lan", "grpc.example", backend)
	grpc.H2C, grpc.ProgressTimeout = true, raised
	plain := route("plain", "lan", "plain.example", backend)
	plain.H2C = true
	_, logs, _ = newTestServer(t, &config.Config{
		Listeners:    []config.Listener{{Name: "lan", Addr: addr, Mode: "tls"}},
		Certificates: map[string]config.Certificate{"grpc.example": certFiles(t, "grpc.example"), "plain.example": certFiles(t, "plain.example")},
		Routes:       []config.Route{grpc, plain},
	})
	return addr, logs
}

// client offers ALPN h2 then http/1.1 and speaks HTTP/2 (h2), or offers and speaks only HTTP/1.1;
// strict waits for a free stream instead of opening another connection.
func client(host string, h2, strict bool) *http.Client {
	p, alpn := new(http.Protocols), []string{"http/1.1"}
	p.SetHTTP2(h2)
	p.SetHTTP1(!h2)
	if h2 {
		alpn = []string{"h2", "http/1.1"}
	}
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: host, InsecureSkipVerify: true, NextProtos: alpn},
		Protocols:       p,
		HTTP2:           &http.HTTP2Config{StrictMaxConcurrentRequests: strict},
	}}
}

func call(t *testing.T, c *http.Client, addr, host, path string, body io.Reader) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", "https://"+addr+path, body)
	req.Host = host
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	req.Header.Set("Origin", "https://ui.example")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

func TestGRPCBidiStream(t *testing.T) {
	backend := forgeBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Host != "grpc.example" || r.Header.Get("Te") != "trailers" ||
			r.Header.Get("Content-Type") != "application/grpc" || r.Header.Get("Origin") != "https://ui.example" {
			http.Error(w, fmt.Sprintf("%s host=%s headers=%v", r.Proto, r.Host, r.Header), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			msg, err := readFrame(r.Body)
			if err == io.EOF {
				break
			} else if err != nil {
				return
			}
			w.Write(grpcFrame(append([]byte("echo:"), msg...)))
			w.(http.Flusher).Flush()
		}
		grpcStatus(w, "3", "bad argument")
	})
	addr, _ := grpcGenkan(t, backend, "400ms")
	pr, pw := io.Pipe()
	defer pw.Close()
	res := call(t, client("grpc.example", true, false), addr, "grpc.example", "/echo.Echo/Bidi", pr)
	if res.StatusCode != http.StatusOK || res.ProtoMajor != 2 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("%s %s: %s", res.Proto, res.Status, b)
	}
	for i, msg := range []string{"a", "b", "c", "after-silence"} {
		if i == 3 {
			time.Sleep(250 * time.Millisecond) // both directions silent: past the default, within the route's
		}
		if _, err := pw.Write(grpcFrame([]byte(msg))); err != nil {
			t.Fatal(err)
		}
		if got, err := readFrame(res.Body); err != nil || string(got) != "echo:"+msg {
			t.Fatalf("message %d: %q, %v", i, got, err)
		}
	}
	pw.Close()
	if _, err := readFrame(res.Body); err != io.EOF {
		t.Fatalf("end of stream: %v", err)
	}
	for k, v := range map[string]string{"Grpc-Status": "3", "Grpc-Message": "bad argument", "Grpc-Status-Details-Bin": "CAMSBGRldGFpbA"} {
		if got := res.Trailer.Get(k); got != v {
			t.Errorf("trailer %s = %q, want %q (trailers %v)", k, got, v, res.Trailer)
		}
	}
}

// A server stream silent past the default timeout passes on a raised route and is cut on a
// default one; a silent stream is cut while a busy sibling on the same connections goes on.
func TestH2CStreamTimeouts(t *testing.T) {
	backend := forgeBackend(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		send := func(msg string) {
			w.Write(grpcFrame([]byte(msg)))
			w.(http.Flusher).Flush()
		}
		switch r.URL.Path {
		case "/silent":
			send("first")
			select {
			case <-time.After(250 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			send("second")
		case "/forever":
			send("first")
			<-r.Context().Done()
			return
		case "/busy":
			for range 16 {
				time.Sleep(50 * time.Millisecond)
				send("tick")
			}
		}
		grpcStatus(w, "0", "")
	})
	addr, _ := grpcGenkan(t, backend, "400ms")
	stream := func(host, path string) (n int, err error) {
		res := call(t, client(host, true, false), addr, host, path, bytes.NewReader(grpcFrame(nil)))
		for {
			if _, err = readFrame(res.Body); err != nil {
				break
			}
			n++
		}
		if err == io.EOF && res.Trailer.Get("Grpc-Status") == "0" {
			err = nil
		}
		return n, err
	}
	if n, err := stream("grpc.example", "/silent"); n != 2 || err != nil {
		t.Errorf("raised route: %d messages, %v; want 2 and grpc-status 0", n, err)
	}
	if n, err := stream("plain.example", "/silent"); n != 1 || err == nil {
		t.Errorf("default route: %d messages, %v; want the stream cut after 1", n, err)
	}

	c := client("grpc.example", true, false) // one connection to genkan, one h2c connection behind it
	type result struct {
		n   int
		err error
		at  time.Time
	}
	run := func(path string, out chan<- result) {
		res := call(t, c, addr, "grpc.example", path, bytes.NewReader(grpcFrame(nil)))
		var r result
		for {
			if _, r.err = readFrame(res.Body); r.err != nil {
				break
			}
			r.n++
		}
		r.at = time.Now()
		out <- r
	}
	silent, busy := make(chan result, 1), make(chan result, 1)
	go run("/forever", silent)
	go run("/busy", busy)
	s, b := <-silent, <-busy
	if s.n != 1 || s.err == nil || !s.at.Before(b.at) {
		t.Errorf("silent stream: %d messages, %v; want cut after 1 while its sibling runs", s.n, s.err)
	}
	if b.n != 16 || b.err != io.EOF {
		t.Errorf("busy sibling: %d messages, %v; want 16 then a clean end", b.n, b.err)
	}
}

// A client-streaming upload of 64 MiB arrives whole: no size cap, no buffering limit.
func TestH2CUpload64MiB(t *testing.T) {
	backend := forgeBackend(t, func(w http.ResponseWriter, r *http.Request) {
		total := 0
		for {
			msg, err := readFrame(r.Body)
			if err != nil {
				break
			}
			total += len(msg)
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Write(grpcFrame([]byte(fmt.Sprint(total))))
		grpcStatus(w, "0", "")
	})
	addr, _ := grpcGenkan(t, backend, "10s")
	pr, pw := io.Pipe()
	go func() {
		chunk := grpcFrame(make([]byte, 1<<20))
		for range 64 {
			if _, err := pw.Write(chunk); err != nil {
				return
			}
		}
		pw.Close()
	}()
	res := call(t, client("grpc.example", true, false), addr, "grpc.example", "/upload", pr)
	msg, err := readFrame(res.Body)
	io.Copy(io.Discard, res.Body)
	if err != nil || string(msg) != fmt.Sprint(64<<20) || res.Trailer.Get("Grpc-Status") != "0" {
		t.Errorf("upload: %q, %v, trailers %v; want %d bytes", msg, err, res.Trailer, 64<<20)
	}
}

// ALPN offers h2 then http/1.1: HTTP/2 clients go h2c to the backend, HTTP/1.1 ones (git, Upgrade)
// stay HTTP/1.1 on an h2c route, and a WebSocket upgrade still works.
func TestH2CRouteProtocols(t *testing.T) {
	backend := forgeBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			io.WriteString(w, r.Proto)
			return
		}
		c, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		buf.Flush()
		io.CopyN(c, buf, 4) // echo
	})
	addr, _ := grpcGenkan(t, backend, "")
	for _, h2 := range []bool{true, false} {
		req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
		req.Host = "grpc.example"
		res, err := client("grpc.example", h2, false).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		want := map[bool]string{true: "HTTP/2.0", false: "HTTP/1.1"}[h2]
		if res.Proto != want || string(body) != want || res.TLS.NegotiatedProtocol != map[bool]string{true: "h2", false: "http/1.1"}[h2] {
			t.Errorf("client h2=%v: client got %s (ALPN %q), backend saw %q", h2, res.Proto, res.TLS.NegotiatedProtocol, body)
		}
	}

	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "grpc.example", InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: grpc.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	buf := bufio.NewReader(c)
	res, err := http.ReadResponse(buf, nil)
	if err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v, %v", res, err)
	}
	c.Write([]byte("ping"))
	if got := make([]byte, 4); func() error { _, err := io.ReadFull(buf, got); return err }() != nil || string(got) != "ping" {
		t.Errorf("WebSocket echo: %q", got)
	}
}

// ADR 0014: genkan advertises 100 concurrent streams; a client honouring it runs 100 at once on one
// connection and its 101st waits until one finishes.
func TestH2StreamCap(t *testing.T) {
	arrived, release, stop := make(chan struct{}, 2*MaxStreams), make(chan struct{}), make(chan struct{})
	defer close(stop) // before the servers close, which wait for their handlers
	backend := forgeBackend(t, func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		select {
		case <-release:
		case <-stop:
		case <-r.Context().Done():
		}
	})
	addr, _ := grpcGenkan(t, backend, "10s")
	c := client("grpc.example", true, true)
	var done atomic.Int32
	start := func() {
		go func() {
			req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
			req.Host = "grpc.example"
			if res, err := c.Do(req); err == nil {
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
			}
			done.Add(1)
		}()
	}
	wait := func(n int, within time.Duration) int {
		got := 0
		for timeout := time.After(within); got < n; got++ {
			select {
			case <-arrived:
			case <-timeout:
				return got
			}
		}
		return got
	}
	// The 101st starts once the 100 run: Go's strict client can deadlock on stream reservations
	// taken while another request waits for a slot.
	for range MaxStreams {
		start()
	}
	if got := wait(MaxStreams, 5*time.Second); got != MaxStreams {
		t.Fatalf("%d streams concurrent, want %d", got, MaxStreams)
	}
	start()
	if got := wait(1, 300*time.Millisecond); got != 0 {
		t.Fatalf("stream %d ran beyond the cap", MaxStreams+1)
	}
	release <- struct{}{}
	if got := wait(1, 3*time.Second); got != 1 {
		t.Fatal("the waiting stream never ran after one finished")
	}
	for range MaxStreams {
		release <- struct{}{}
	}
	eventually(t, "every request finished", func() bool { return done.Load() == MaxStreams+1 })
}

// Credentials in headers, cookies and the query string never reach the access log.
func TestAccessLogOmitsSecrets(t *testing.T) {
	addr, logs := grpcGenkan(t, forgeBackend(t, func(http.ResponseWriter, *http.Request) {}), "")
	for _, h2 := range []bool{true, false} {
		req, _ := http.NewRequest("GET", "https://"+addr+"/api?access_token=secret-query&token=secret-token", nil)
		req.Host = "grpc.example"
		req.Header.Set("Authorization", "Bearer secret-bearer")
		req.Header.Set("Cookie", "session=secret-cookie")
		req.Header.Set("X-Api-Token", "secret-header")
		req.Header.Set("Proxy-Authorization", "Basic secret-proxy")
		res, err := client("grpc.example", h2, false).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}
	eventually(t, "two request lines", func() bool { return strings.Count(logs.String(), `"event":"request"`) == 2 })
	if strings.Contains(logs.String(), "secret") {
		t.Errorf("a credential reached the logs: %s", logs.String())
	}
}
