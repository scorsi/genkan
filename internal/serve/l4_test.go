package serve

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/pires/go-proxyproto"

	"github.com/scorsi/genkan/internal/config"
	"github.com/scorsi/genkan/internal/logging"
	"github.com/scorsi/genkan/internal/metrics"
)

// clientHello returns the bytes a TLS client sends first for sni.
func clientHello(t *testing.T, sni string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		tls.Client(client, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake()
		client.Close()
	}()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(server, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

// fragment splits a single-record ClientHello into records of at most size handshake bytes.
func fragment(record []byte, size int) []byte {
	var out []byte
	for body := record[5:]; len(body) > 0; {
		n := min(size, len(body))
		out = append(out, record[0], record[1], record[2], byte(n>>8), byte(n))
		out = append(out, body[:n]...)
		body = body[n:]
	}
	return out
}

func TestPeek(t *testing.T) {
	hello := clientHello(t, "Pass.Example")
	trailing := []byte("rest of the stream")
	for name, stream := range map[string][]byte{
		"one record":   hello,
		"many records": fragment(hello, 7),
	} {
		t.Run(name, func(t *testing.T) {
			input := append(bytes.Clone(stream), trailing...)
			// One byte per read: the ClientHello spans as many reads as it has bytes.
			c := &conn{r: iotest.OneByteReader(bytes.NewReader(input))}
			sni, ok, err := c.peek()
			if !ok || sni != "pass.example" {
				t.Fatalf("sni=%q ok=%v err=%v", sni, ok, err)
			}
			replayed, _ := io.ReadAll(c.r)
			if !bytes.Equal(replayed, input) {
				t.Fatalf("replayed %d bytes, want the %d bytes read", len(replayed), len(input))
			}
		})
	}
	c := &conn{r: strings.NewReader("GET / HTTP/1.1\r\n\r\n")}
	if _, ok, err := c.peek(); ok || err == nil {
		t.Errorf("plaintext peeked as a ClientHello: ok=%v err=%v", ok, err)
	}
	if replayed, _ := io.ReadAll(c.r); string(replayed) != "GET / HTTP/1.1\r\n\r\n" {
		t.Errorf("plaintext replay: %q", replayed)
	}
}

// tcpServer accepts on a fresh address and runs handle on each connection.
func tcpServer(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handle(c)
			}()
		}
	}()
	return ln.Addr().String()
}

func newTestServer(t *testing.T, cfg *config.Config) (*Server, *syncBuffer, *metrics.Registry) {
	t.Helper()
	logs, m := new(syncBuffer), metrics.New("test")
	s := New(logging.New(logs, slog.LevelInfo), new(slog.LevelVar), m)
	cfg.Log = config.Log{Level: "info", Access: true}
	if errs, _ := cfg.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	if err := s.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(0) })
	return s, logs, m
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Errorf("never: %s", what)
}

func scrape(m *metrics.Registry) string {
	var out strings.Builder
	m.Write(&out)
	return out.String()
}

// A tls listener forwards a matching SNI raw, peeked bytes included, with a PROXY v2 header, and
// still terminates TLS for its http routes.
func TestPassthroughBySNI(t *testing.T) {
	headers := make(chan *proxyproto.Header, 1)
	backendCert := selfSigned(t, "backend.example")
	pass := tcpServer(t, func(c net.Conn) {
		br := bufio.NewReader(c)
		h, err := proxyproto.Read(br)
		headers <- h
		if err != nil {
			return
		}
		tc := tls.Server(&conn{Conn: c, r: br}, &tls.Config{Certificates: []tls.Certificate{*backendCert}})
		io.Copy(tc, tc) // echo
	})
	pub := config.Listener{Name: "pub", Addr: freeAddr(t), Mode: "tls"}
	_, logs, m := newTestServer(t, &config.Config{
		Listeners:    []config.Listener{pub},
		Certificates: map[string]config.Certificate{"a.example": certFiles(t, "a.example")},
		Routes: []config.Route{
			route("a", "pub", "a.example", backend(t, "A")),
			{Name: "pass", Type: "tcp", Listeners: []string{"pub"}, SNI: []string{"pass.example"}, Backend: pass, SendProxy: "v2"},
		},
	})

	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", pub.Addr, &tls.Config{ServerName: "pass.example", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.ConnectionState().PeerCertificates[0].Subject.CommonName; got != "backend.example" {
		t.Errorf("TLS ended at %q, not at the backend", got)
	}
	io.WriteString(c, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Errorf("echo: %q %v", buf, err)
	}
	h := <-headers
	if h == nil || h.SourceAddr.String() != c.LocalAddr().String() || h.DestinationAddr.String() != pub.Addr {
		t.Errorf("PROXY header %+v, want source %s destination %s", h, c.LocalAddr(), pub.Addr)
	}
	c.Close()

	if got := get(pub.Addr, "a.example"); got != "A" {
		t.Errorf("terminated route next to passthrough: %q", got)
	}
	eventually(t, "connection logged and counted", func() bool {
		return strings.Contains(logs.String(), `"event":"connection","listener":"pub","route":"pass","client":"127.0.0.1","sni":"pass.example","bytes_in":`) &&
			strings.Contains(scrape(m), `genkan_connections_total{listener="pub",route="pass"} 1`)
	})
}

// Unknown SNI on a listener without http or static routes closes the connection: no TLS alert,
// nothing forwarded.
func TestUnknownSNIOnPassthroughListener(t *testing.T) {
	forwarded := make(chan struct{}, 1)
	pass := tcpServer(t, func(net.Conn) { forwarded <- struct{}{} })
	pub := config.Listener{Name: "pub", Addr: freeAddr(t), Mode: "tls"}
	_, logs, m := newTestServer(t, &config.Config{
		Listeners: []config.Listener{pub},
		Routes:    []config.Route{{Name: "pass", Type: "tcp", Listeners: []string{"pub"}, SNI: []string{"pass.example"}, Backend: pass}},
	})
	for _, sni := range []string{"other.example", ""} {
		_, err := tls.Dial("tcp", pub.Addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		if err == nil || strings.Contains(err.Error(), "unrecognized name") {
			t.Errorf("sni %q: %v, want the connection closed without an alert", sni, err)
		}
	}
	select {
	case <-forwarded:
		t.Error("unknown SNI reached the backend")
	case <-time.After(50 * time.Millisecond):
	}
	eventually(t, "rejections logged and counted", func() bool {
		return strings.Contains(logs.String(), `"event":"connection-rejected","listener":"pub","client":"127.0.0.1:`) &&
			strings.Contains(scrape(m), `genkan_connections_rejected_total{listener="pub",reason="unknown-sni"} 2`)
	})
}

// A tcp listener forwards the whole port; a half-close travels to the backend, which answers after
// reading to EOF, and the backend's close travels back.
func TestTCPListenerHalfClose(t *testing.T) {
	ssh := tcpServer(t, func(c net.Conn) {
		b, _ := io.ReadAll(c) // returns at the client's half-close
		io.WriteString(c, "got "+string(b))
	})
	l := config.Listener{Name: "ssh", Addr: freeAddr(t), Mode: "tcp"}
	newTestServer(t, &config.Config{
		Listeners: []config.Listener{l},
		Routes:    []config.Route{{Name: "git-ssh", Type: "tcp", Listeners: []string{"ssh"}, Backend: ssh}},
	})
	c, err := net.Dial("tcp", l.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "SSH-2.0-test")
	c.(*net.TCPConn).CloseWrite()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if b, err := io.ReadAll(c); err != nil || string(b) != "got SSH-2.0-test" {
		t.Errorf("reply %q %v", b, err)
	}
}

func proxyHeader(t *testing.T, c net.Conn, src string) {
	t.Helper()
	h := proxyproto.HeaderProxyFromAddrs(2, net.TCPAddrFromAddrPort(netip.MustParseAddrPort(src)), c.RemoteAddr())
	if _, err := h.WriteTo(c); err != nil {
		t.Fatal(err)
	}
}

// accept_proxy: the header's client feeds X-Forwarded-For and the access log; a missing header, a
// v1 header or an untrusted peer is closed before TLS. G8: a public SNI does not reach a host that
// is bound to another listener only.
func TestAcceptProxy(t *testing.T) {
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Host+" for="+r.Header.Get("X-Forwarded-For"))
	})
	b := httptest.NewServer(echo)
	defer b.Close()
	backendURL := b.URL
	lan := config.Listener{Name: "lan", Addr: freeAddr(t), Mode: "tls"}
	edge := config.Listener{Name: "edge", Addr: freeAddr(t), Mode: "tls", AcceptProxy: "required", TrustedSources: []string{"127.0.0.0/8"}}
	closed := config.Listener{Name: "closed", Addr: freeAddr(t), Mode: "tls", AcceptProxy: "required", TrustedSources: []string{"192.0.2.0/24"}}
	public := route("public", "lan", "public.example", backendURL)
	public.Listeners = []string{"lan", "edge", "closed"}
	_, logs, m := newTestServer(t, &config.Config{
		Listeners: []config.Listener{lan, edge, closed},
		Certificates: map[string]config.Certificate{
			"public.example": certFiles(t, "public.example"), "internal.example": certFiles(t, "internal.example"),
		},
		Routes: []config.Route{public, route("internal", "lan", "internal.example", backendURL)},
	})

	request := func(addr, sni, host string, header func(net.Conn)) string {
		c := &http.Client{Transport: &http.Transport{
			DialContext: func(_ context.Context, network, a string) (net.Conn, error) {
				c, err := net.Dial(network, a)
				if err == nil && header != nil {
					header(c)
				}
				return c, err
			},
			TLSClientConfig:   &tls.Config{ServerName: sni, InsecureSkipVerify: true},
			DisableKeepAlives: true,
		}}
		req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
		req.Host = host
		res, err := c.Do(req)
		if err != nil {
			return ""
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.Status[:3] + " " + string(b)
	}
	from := func(src string) func(net.Conn) { return func(c net.Conn) { proxyHeader(t, c, src) } }

	if got := request(edge.Addr, "public.example", "public.example", from("203.0.113.7:4242")); got != "200 public.example for=203.0.113.7" {
		t.Errorf("through PROXY: %q", got)
	}
	if got := request(edge.Addr, "public.example", "internal.example", from("203.0.113.7:4242")); !strings.HasPrefix(got, "404") {
		t.Errorf("internal Host on the edge listener: %q, want 404", got)
	}
	if got := request(lan.Addr, "internal.example", "internal.example", nil); got != "200 internal.example for=127.0.0.1" {
		t.Errorf("internal on lan: %q", got)
	}
	if got := request(edge.Addr, "public.example", "public.example", nil); got != "" {
		t.Errorf("no header: %q, want the connection closed", got)
	}
	v1 := func(c net.Conn) { io.WriteString(c, "PROXY TCP4 203.0.113.7 127.0.0.1 4242 443\r\n") }
	if got := request(edge.Addr, "public.example", "public.example", v1); got != "" {
		t.Errorf("v1 header: %q, want the connection closed", got)
	}
	if got := request(closed.Addr, "public.example", "public.example", from("203.0.113.7:4242")); got != "" {
		t.Errorf("untrusted peer: %q, want the connection closed", got)
	}
	eventually(t, "client from the header logged, rejections counted", func() bool {
		out := scrape(m)
		return strings.Contains(logs.String(), `"event":"request","listener":"edge","route":"public","client":"203.0.113.7"`) &&
			strings.Contains(out, `genkan_connections_rejected_total{listener="edge",reason="proxy-header"} 2`) &&
			strings.Contains(out, `genkan_connections_rejected_total{listener="closed",reason="untrusted-peer"} 1`)
	})
}

// ADR 0007: 5 s from accept to a complete PROXY header or ClientHello.
func TestPeekDeadline(t *testing.T) {
	old := PeekTimeout
	PeekTimeout = 100 * time.Millisecond
	defer func() { PeekTimeout = old }()
	pass := tcpServer(t, func(net.Conn) {})
	pub := config.Listener{Name: "pub", Addr: freeAddr(t), Mode: "tls"}
	edge := config.Listener{Name: "edge", Addr: freeAddr(t), Mode: "tls", AcceptProxy: "required", TrustedSources: []string{"127.0.0.0/8"}}
	_, _, m := newTestServer(t, &config.Config{
		Listeners: []config.Listener{pub, edge},
		Routes:    []config.Route{{Name: "pass", Type: "tcp", Listeners: []string{"pub", "edge"}, SNI: []string{"pass.example"}, Backend: pass}},
	})
	for _, addr := range []string{pub.Addr, edge.Addr} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = c.Read(make([]byte, 1))
		var ne net.Error
		if err == nil || errors.As(err, &ne) && ne.Timeout() {
			t.Errorf("%s: silent connection still open (%v)", addr, err)
		}
		c.Close()
	}
	eventually(t, "both deadlines counted", func() bool {
		out := scrape(m)
		return strings.Contains(out, `genkan_connections_rejected_total{listener="pub",reason="client-hello"} 1`) &&
			strings.Contains(out, `genkan_connections_rejected_total{listener="edge",reason="proxy-header"} 1`)
	})
}

// ADR 0007: the idle timeout counts both directions; traffic one way keeps a silent reverse
// direction open, silence both ways closes the connection.
func TestPassthroughIdle(t *testing.T) {
	old := PassthroughIdle
	PassthroughIdle = 150 * time.Millisecond
	defer func() { PassthroughIdle = old }()
	received := make(chan int, 1)
	sink := tcpServer(t, func(c net.Conn) {
		n, _ := io.Copy(io.Discard, c)
		received <- int(n)
	})
	l := config.Listener{Name: "ssh", Addr: freeAddr(t), Mode: "tcp"}
	newTestServer(t, &config.Config{
		Listeners: []config.Listener{l},
		Routes:    []config.Route{{Name: "sink", Type: "tcp", Listeners: []string{"ssh"}, Backend: sink}},
	})
	c, err := net.Dial("tcp", l.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for range 8 { // 400 ms of one-way traffic
		io.WriteString(c, "x")
		time.Sleep(50 * time.Millisecond)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("idle connection not closed: %v", err)
	}
	if n := <-received; n != 8 {
		t.Errorf("backend received %d bytes, want 8: the silent direction cut the connection", n)
	}
}

// A reload that drops a listener closes its passthrough connections (ADR 0003, no draining).
func TestReloadClosesPassthrough(t *testing.T) {
	hold := tcpServer(t, func(c net.Conn) { io.Copy(c, c) })
	ssh := config.Listener{Name: "ssh", Addr: freeAddr(t), Mode: "tcp"}
	lan := config.Listener{Name: "lan", Addr: freeAddr(t), Mode: "tcp"}
	cfg := &config.Config{
		Listeners: []config.Listener{ssh, lan},
		Routes: []config.Route{
			{Name: "a", Type: "tcp", Listeners: []string{"ssh"}, Backend: hold},
			{Name: "b", Type: "tcp", Listeners: []string{"lan"}, Backend: hold},
		},
	}
	s, _, _ := newTestServer(t, cfg)
	c, err := net.Dial("tcp", ssh.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "x")
	io.ReadFull(c, make([]byte, 1)) // forwarded and tracked

	cfg.Listeners, cfg.Routes = cfg.Listeners[1:], cfg.Routes[1:]
	if err := s.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("connection of a removed listener still open: %v", err)
	}
}

// The other way round: the backend half-closes first and still reads what the client sends after.
func TestTCPListenerBackendHalfClose(t *testing.T) {
	got := make(chan string, 1)
	ssh := tcpServer(t, func(c net.Conn) {
		io.WriteString(c, "banner")
		c.(*net.TCPConn).CloseWrite()
		b, _ := io.ReadAll(c)
		got <- string(b)
	})
	l := config.Listener{Name: "ssh", Addr: freeAddr(t), Mode: "tcp"}
	newTestServer(t, &config.Config{
		Listeners: []config.Listener{l},
		Routes:    []config.Route{{Name: "git-ssh", Type: "tcp", Listeners: []string{"ssh"}, Backend: ssh}},
	})
	c, err := net.Dial("tcp", l.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if b, err := io.ReadAll(c); err != nil || string(b) != "banner" {
		t.Fatalf("banner %q %v", b, err)
	}
	io.WriteString(c, "after the backend's half-close")
	c.(*net.TCPConn).CloseWrite()
	select {
	case b := <-got:
		if b != "after the backend's half-close" {
			t.Errorf("backend read %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Error("backend never read the client's data")
	}
}
