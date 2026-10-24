package serve

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"

	"github.com/scorsi/genkan/internal/router"
)

// L4 limits of ADR 0007. Variables rather than constants so tests can shrink them.
var (
	// PeekTimeout bounds the time from accept to a complete PROXY header and ClientHello.
	PeekTimeout = 5 * time.Second
	// PassthroughIdle closes a forwarded connection after this long without a byte either way.
	PassthroughIdle = time.Hour
)

// tcpRoute is a `tcp` route as one listener sees it.
type tcpRoute struct {
	name, backend string
	sendProxy     bool
}

// conn is an accepted connection whose first bytes genkan has read: Read replays them first, and
// the addresses are those of the PROXY header on an accept_proxy listener, the socket's otherwise.
type conn struct {
	net.Conn
	r             io.Reader
	remote, local net.Addr
}

func (c *conn) Read(b []byte) (int, error) { return c.r.Read(b) }
func (c *conn) RemoteAddr() net.Addr       { return c.remote }
func (c *conn) LocalAddr() net.Addr        { return c.local }
func (c *conn) CloseWrite() error          { return closeWrite(c.Conn) }

// closeWrite half-closes c when it can (TCP), and closes it otherwise.
func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// readProxy authenticates the TCP peer against trusted, then requires a PROXY v2 header (ADR 0002).
// It returns the rejection reason with the error.
func (c *conn) readProxy(trusted []*net.IPNet) (string, error) {
	peer, _ := c.remote.(*net.TCPAddr)
	if peer == nil || !slices.ContainsFunc(trusted, func(n *net.IPNet) bool { return n.Contains(peer.IP) }) {
		return "untrusted-peer", fmt.Errorf("peer %v not in trusted_sources", c.remote)
	}
	br := bufio.NewReader(c.r)
	h, err := proxyproto.Read(br)
	if err == nil && h.Version != 2 {
		err = errors.New("PROXY protocol v1 header, v2 required")
	}
	if err != nil {
		return "proxy-header", err
	}
	c.r = br
	// A LOCAL header (the sender's own health check) carries no client: the peer stays.
	if src, dst, ok := h.TCPAddrs(); ok && h.Command.IsProxy() {
		c.remote, c.local = src, dst
	}
	return "", nil
}

var errPeeked = errors.New("client hello read")

// peek reads the ClientHello without answering it: crypto/tls parses it, records spread over
// several reads or records included, and every byte it consumed is replayed by later reads. The
// size is bounded by crypto/tls's handshake message limit, the time by the caller's deadline.
func (c *conn) peek() (sni string, ok bool, err error) {
	var read bytes.Buffer
	err = tls.Server(helloConn{r: io.TeeReader(c.r, &read)}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni, ok = strings.ToLower(hello.ServerName), true
			return nil, errPeeked
		},
	}).Handshake()
	c.r = io.MultiReader(&read, c.r)
	return sni, ok, err
}

// helloConn feeds crypto/tls during peek; what it writes (an alert) never reaches the client.
type helloConn struct {
	net.Conn // nil: crypto/tls only reads and writes during a server handshake
	r        io.Reader
}

func (h helloConn) Read(b []byte) (int, error)  { return h.r.Read(b) }
func (h helloConn) Write(b []byte) (int, error) { return len(b), nil }

// dispatch routes one accepted connection with the listener's state at accept: a whole tcp
// listener, or a tls listener's SNI, goes to its tcp route; other ClientHellos go to the TLS
// server, and on a listener with no http or static route they are closed instead.
func (s *Server) dispatch(sl *slot, raw net.Conn) {
	st := sl.state.Load()
	start := time.Now()
	raw.SetReadDeadline(start.Add(PeekTimeout))
	c := &conn{Conn: raw, r: raw, remote: raw.RemoteAddr(), local: raw.LocalAddr()}
	if st.trusted != nil {
		if reason, err := c.readProxy(st.trusted); err != nil {
			s.reject(st, c, reason)
			return
		}
	}
	sni := "-"
	r, ok := st.tcp[""] // the route of a tcp listener
	if st.mode == "tls" {
		name, hello, err := c.peek()
		switch {
		case hello:
			sni = name
			if r, ok = st.tcp[name]; !ok && !st.terminates {
				s.reject(st, c, "unknown-sni")
				return
			}
		case !st.terminates || errors.Is(err, os.ErrDeadlineExceeded):
			s.reject(st, c, "client-hello")
			return
		}
		// Not a ClientHello on a terminating listener: the TLS server fails it as in v0, logged as
		// tls-handshake-error (a plaintext HTTP request still gets net/http's 400).
	}
	raw.SetReadDeadline(time.Time{})
	if !ok {
		sl.handoff.push(c)
		return
	}
	s.forward(sl, st, r, c, sni, start)
}

func (s *Server) reject(st *state, c *conn, reason string) {
	c.Close()
	s.metrics.Rejected(st.listener, reason)
	// info and no error text: a public edge is scanned all day; reason and counter suffice (ADR 0012).
	s.log.Info("", "event", "connection-rejected", "listener", st.listener, "client", c.remote.String(), "reason", reason)
}

// forward copies c to r's backend and back until both directions end (ADR 0007 idle and
// half-close), then logs and counts the connection.
func (s *Server) forward(sl *slot, st *state, r tcpRoute, c *conn, sni string, start time.Time) {
	defer c.Close()
	b, err := net.DialTimeout("tcp", r.backend, router.DialTimeout)
	if err != nil {
		s.metrics.UpstreamError(r.name)
		s.log.Warn("", "event", "upstream-error", "listener", st.listener, "route", r.name, "err", err.Error())
		return
	}
	defer b.Close()
	if !sl.track(c, b) {
		return // the listener closed meanwhile
	}
	defer sl.untrack(c)
	if r.sendProxy {
		b.SetWriteDeadline(time.Now().Add(PassthroughIdle))
		if _, err := proxyproto.HeaderProxyFromAddrs(2, c.remote, c.local).WriteTo(b); err != nil {
			s.metrics.UpstreamError(r.name)
			s.log.Warn("", "event", "upstream-error", "listener", st.listener, "route", r.name, "err", err.Error())
			return
		}
	}
	in, out := pipe(c, b, PassthroughIdle)
	s.metrics.Connection(st.listener, r.name, in, out)
	if st.access {
		s.log.Info("",
			"event", "connection",
			"listener", st.listener,
			"route", r.name,
			"client", hostOnly(c.remote),
			"sni", sni,
			"bytes_in", in,
			"bytes_out", out,
			"dur_us", time.Since(start).Microseconds(),
		)
	}
}

func hostOnly(a net.Addr) string {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.IP.String()
	}
	return a.String()
}

// pipe copies both ways until both directions end and returns the bytes copied client to backend
// (in) and back (out). A direction that reaches EOF half-closes its destination and the other one
// goes on; any other error closes both. The idle deadline is shared: a direction waiting on a
// silent peer keeps waiting while the other one moves.
func pipe(client, backend net.Conn, idle time.Duration) (in, out int64) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var wg sync.WaitGroup
	wg.Go(func() { out = copyIdle(client, backend, &last, idle) })
	in = copyIdle(backend, client, &last, idle)
	wg.Wait()
	return in, out
}

func copyIdle(dst, src net.Conn, last *atomic.Int64, idle time.Duration) (n int64) {
	buf := make([]byte, 32<<10)
	for {
		src.SetReadDeadline(time.Unix(0, last.Load()).Add(idle))
		nr, err := src.Read(buf)
		if nr > 0 {
			last.Store(time.Now().UnixNano())
			dst.SetWriteDeadline(time.Now().Add(idle))
			nw, werr := dst.Write(buf[:nr])
			n += int64(nw)
			if werr != nil {
				err = werr
			}
		}
		switch {
		case err == nil:
		case errors.Is(err, os.ErrDeadlineExceeded) && time.Since(time.Unix(0, last.Load())) < idle:
			// the other direction moved since this read started
		case err == io.EOF:
			closeWrite(dst)
			return n
		default:
			src.Close()
			dst.Close()
			return n
		}
	}
}

// handoff is the listener the http.Server serves: dispatch pushes it the connections whose TLS
// genkan terminates.
type handoff struct {
	addr  net.Addr
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newHandoff(addr net.Addr) *handoff {
	return &handoff{addr: addr, conns: make(chan net.Conn), done: make(chan struct{})}
}

func (h *handoff) Accept() (net.Conn, error) {
	select {
	case c := <-h.conns:
		return c, nil
	case <-h.done:
		return nil, net.ErrClosed
	}
}

func (h *handoff) Close() error {
	h.once.Do(func() { close(h.done) })
	return nil
}

func (h *handoff) Addr() net.Addr { return h.addr }

func (h *handoff) push(c net.Conn) {
	select {
	case h.conns <- c:
	case <-h.done:
		c.Close()
	}
}
