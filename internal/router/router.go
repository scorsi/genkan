// Package router routes HTTP requests by Host and logs them.
package router

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scorsi/genkan/internal/logging"
	"github.com/scorsi/genkan/internal/metrics"
)

// Limits of ADR 0007. Variables rather than constants so tests can shrink them.
var (
	// ProgressTimeout cuts a request body or a response that makes no progress for this long.
	ProgressTimeout = 60 * time.Second
	// DialTimeout bounds the connection to a backend.
	DialTimeout = 5 * time.Second
)

// transport is shared by every proxy handler: the backends are few and local.
var transport = upstreamTransport{&http.Transport{
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{Timeout: DialTimeout}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &upstreamConn{Conn: c, timeout: ProgressTimeout}, nil
	},
	MaxIdleConnsPerHost: 32,
	IdleConnTimeout:     90 * time.Second,
}}

// Router serves one listener: it picks the route by Host, writes one access record per request and
// counts it.
type Router struct {
	listener string
	log      *slog.Logger
	access   bool
	metrics  *metrics.Registry
	routes   map[string]entry
	fallback *entry        // serves the hosts routes lacks; nil: 404
	budget   chan struct{} // in-flight requests on the listener, shared across reloads; nil: unbounded
}

type entry struct {
	name  string
	h     http.Handler
	quiet map[string]bool // paths not logged when they succeed (ADR 0011)
}

func New(listener string, log *slog.Logger, access bool, m *metrics.Registry) *Router {
	return &Router{listener: listener, log: log, access: access, metrics: m, routes: map[string]entry{}}
}

// Handle serves host (lowercase, no port) with h. route is the name used in logs. A request to
// one of quiet (exact paths) that completes with a status below 400 is counted but not logged.
func (r *Router) Handle(host, route string, h http.Handler, quiet ...string) {
	e := entry{name: route, h: h}
	for _, p := range quiet {
		if e.quiet == nil {
			e.quiet = map[string]bool{}
		}
		e.quiet[p] = true
	}
	r.routes[host] = e
}

// Default serves every host Handle did not register with h, logged as route.
func (r *Router) Default(route string, h http.Handler) { r.fallback = &entry{name: route, h: h} }

// Budget bounds the requests in flight through r with slots: one is held from routing to the end
// of the response, and a request finding none free is answered 503 at once, without waiting.
func (r *Router) Budget(slots chan struct{}) { r.budget = slots }

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	// Bound I/O, not backend processing or buffering between writes (ADR 0007).
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{})
	rec := &recorder{ResponseWriter: w, rc: rc, status: http.StatusOK}
	// net/http must retain its original body to detect early Close and disable keep-alive.
	req = req.WithContext(req.Context())
	var body *progressReader
	if req.Body != nil && req.Body != http.NoBody {
		body = &progressReader{ReadCloser: req.Body, rc: rc}
		req.Body = body
		if req.ProtoMajor == 1 {
			rec.input = body
		}
	}
	e, ok := r.routes[hostOnly(req.Host)]
	if !ok && r.fallback != nil {
		e, ok = *r.fallback, true
	}
	if !ok {
		e.name = "-" // the log schema's "no route"
	}
	// Deferred: ReverseProxy aborts a response that fails mid-body by panicking with
	// http.ErrAbortHandler; the request is still logged and counted, then the panic goes on.
	returned := false // false while panicking: an aborted response is never quiet
	defer func() {
		if !rec.hijacked {
			rec.closeInput()
			rec.push() // net/http flushes its final buffered output after ServeHTTP returns
		}
		if body != nil {
			body.finish()
		}
		r.done(req, e.name, rec, start, returned && rec.status < 400 && e.quiet[req.URL.Path])
	}()
	admitted := true
	if ok && r.budget != nil {
		select {
		case r.budget <- struct{}{}:
			defer func() { <-r.budget }()
		default:
			admitted = false
		}
	}
	switch {
	case !ok:
		http.NotFound(rec, req)
	case !admitted:
		http.Error(rec, "busy", http.StatusServiceUnavailable)
	default:
		e.h.ServeHTTP(rec, req)
	}
	returned = true
}

func (r *Router) done(req *http.Request, route string, rec *recorder, start time.Time, quiet bool) {
	d := time.Since(start)
	r.metrics.Request(r.listener, route, req.Method, rec.status, rec.bytes, d)
	if r.access && !quiet {
		r.log.Info("",
			"event", "request",
			"listener", r.listener,
			"route", route,
			"client", hostOnly(req.RemoteAddr),
			"method", req.Method,
			"host", hostOnly(req.Host),
			"path", req.URL.Path,
			"proto", req.Proto,
			"tls", tlsVersion(req.TLS),
			"status", rec.status,
			"bytes", rec.bytes,
			"dur_us", d.Microseconds(),
			"user_agent", req.UserAgent(),
		)
	}
}

// tlsVersion is "1.3" for TLS 1.3, "-" without TLS.
func tlsVersion(cs *tls.ConnectionState) string {
	if cs == nil {
		return "-"
	}
	return strings.TrimPrefix(tls.VersionName(cs.Version), "TLS ")
}

// Proxy forwards to backend, keeping the client's Host and overwriting X-Forwarded-For, -Host and
// -Proto with values genkan trusts (ReverseProxy strips the client's copies before Rewrite runs).
// A backend that fails answers 502, logged as upstream-error and counted on route.
func Proxy(backend *url.URL, listener, route string, log *slog.Logger, m *metrics.Registry) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(backend)
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			// A client that went away is not the backend's fault (httputil's default handler agrees).
			if !errors.Is(err, context.Canceled) {
				m.UpstreamError(route)
				log.Warn("", "event", "upstream-error", "listener", listener, "route", route, "err", err.Error())
			}
			w.WriteHeader(http.StatusBadGateway)
		},
		// What ReverseProxy still logs itself: a copy error once the response has started.
		ErrorLog: logging.Std(log, func(string) string { return "proxy-error" }),
	}
}

// Redirect answers every request 301 to https:// on the request's host, port dropped (443), same
// path and query, whatever the method. A request without a usable Host gets 400.
func Redirect() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		host := strings.ToLower((&url.URL{Host: req.Host}).Hostname())
		if host == "" {
			http.Error(w, "missing Host", http.StatusBadRequest)
			return
		}
		if strings.Contains(host, ":") {
			host = "[" + host + "]" // IPv6 literal
		}
		uri := req.URL.RequestURI()
		if !strings.HasPrefix(uri, "/") { // an opaque request URI; net/http answers OPTIONS * itself
			uri = "/"
		}
		http.Redirect(w, req, "https://"+host+uri, http.StatusMovedPermanently)
	})
}

// Static serves the files under root: index.html for a directory, 404 for a directory without one
// (no listing) and for anything missing. No SPA fallback.
func Static(root string) http.Handler {
	return http.FileServer(noListing{http.Dir(root)})
}

// noListing hides directories that have no index.html, so http.FileServer never lists them.
type noListing struct{ fs http.FileSystem }

func (n noListing) Open(name string) (http.File, error) {
	f, err := n.fs.Open(name)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err == nil && st.IsDir() {
		index, err := n.fs.Open(path.Join(name, "index.html"))
		if err != nil {
			f.Close()
			return nil, err
		}
		index.Close()
	}
	return f, nil
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(hostport)
}

// progressReader bounds explicit reads and net/http's bounded discard inside Close. The transport
// may still read or close the body after the handler returned (backend answered early): rc belongs
// to the finished request then (HTTP/2 frees it), so mu serialises rc calls with finish.
type progressReader struct {
	io.ReadCloser
	rc     *http.ResponseController
	mu     sync.Mutex
	closed bool
	done   bool
}

// deadline sets the read deadline unless the handler returned or, for a reset, Close took over.
func (p *progressReader) deadline(d time.Time, reset bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.done && !(reset && p.closed) {
		p.rc.SetReadDeadline(d)
	}
}

func (p *progressReader) Read(b []byte) (int, error) {
	p.deadline(time.Now().Add(ProgressTimeout), false)
	defer p.deadline(time.Time{}, true)
	return p.ReadCloser.Read(b)
}

func (p *progressReader) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	p.deadline(time.Now().Add(ProgressTimeout), false)
	defer p.deadline(time.Time{}, false)
	return p.ReadCloser.Close()
}

// finish runs before the handler returns; later reads and closes leave rc alone.
func (p *progressReader) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done = true
}

type recorder struct {
	http.ResponseWriter
	rc          *http.ResponseController
	input       io.Closer // HTTP/1 body to close before net/http can drain it without a deadline
	wroteHeader bool
	hijacked    bool
	status      int
	bytes       int64
}

func (r *recorder) closeInput() {
	if r.input != nil {
		r.input.Close() // net/http closes the connection if the original body did not reach EOF
	}
}

func (r *recorder) push() { r.rc.SetWriteDeadline(time.Now().Add(ProgressTimeout)) }

func (r *recorder) WriteHeader(code int) {
	if !r.wroteHeader && (code >= 200 || code == http.StatusSwitchingProtocols) {
		r.closeInput()
		r.wroteHeader = true
		r.status = code
	}
	r.push()
	defer r.rc.SetWriteDeadline(time.Time{})
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	r.push()
	defer r.rc.SetWriteDeadline(time.Time{})
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *recorder) FlushError() error {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	r.push()
	defer r.rc.SetWriteDeadline(time.Time{})
	return r.rc.Flush()
}

func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, buf, err := r.rc.Hijack()
	if err == nil {
		// Only ReverseProxy hijacks, to write a backend's 101 itself on the raw connection.
		r.hijacked = true
		r.status = http.StatusSwitchingProtocols
	}
	return c, buf, err
}

// Unwrap lets http.ResponseController reach other optional writer methods.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// upstreamTransport enables read deadlines only after final headers, preserving the unlimited
// header wait and the bidirectional body ReverseProxy needs for a 101 upgrade.
type upstreamTransport struct{ *http.Transport }

func (t upstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body := new(atomic.Bool)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			info.Conn.(*upstreamConn).body.Store(body)
		},
		// A pooled connection may already belong to another request when this hook runs.
		PutIdleConn: func(error) { body.Store(false) },
	}))
	res, err := t.Transport.RoundTrip(req)
	if err == nil && res.Body != http.NoBody && res.StatusCode != http.StatusSwitchingProtocols {
		body.Store(true)
	}
	return res, err
}

// upstreamConn measures body inactivity below HTTP buffering, on each network Read.
type upstreamConn struct {
	net.Conn
	timeout time.Duration
	body    atomic.Pointer[atomic.Bool]
}

func (c *upstreamConn) Read(b []byte) (int, error) {
	if body := c.body.Load(); body != nil && body.Load() {
		c.SetReadDeadline(time.Now().Add(c.timeout))
		defer c.SetReadDeadline(time.Time{})
	}
	return c.Conn.Read(b)
}

func (c *upstreamConn) Write(b []byte) (int, error) {
	c.SetWriteDeadline(time.Now().Add(c.timeout))
	defer c.SetWriteDeadline(time.Time{})
	return c.Conn.Write(b)
}
