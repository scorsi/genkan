// Package router routes HTTP requests by Host and logs them.
package router

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
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
var transport = &http.Transport{
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{Timeout: DialTimeout}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return upstreamConn{c}, nil
	},
	MaxIdleConnsPerHost: 32,
	IdleConnTimeout:     90 * time.Second,
}

// Router serves one listener: it picks the route by Host, writes one access record per request and
// counts it.
type Router struct {
	listener string
	log      *slog.Logger
	access   bool
	metrics  *metrics.Registry
	routes   map[string]entry
}

type entry struct {
	name string
	h    http.Handler
}

func New(listener string, log *slog.Logger, access bool, m *metrics.Registry) *Router {
	return &Router{listener: listener, log: log, access: access, metrics: m, routes: map[string]entry{}}
}

// Handle serves host (lowercase, no port) with h. route is the name used in logs.
func (r *Router) Handle(host, route string, h http.Handler) {
	r.routes[host] = entry{route, h}
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	// Idle-based deadlines (ADR 0007), each on the direction in use only: the read deadline while a
	// body Read is pending, the write deadline from the first byte of output on, pushed by progress
	// in either direction. None waits on the backend's headers, and no read deadline is left for
	// HTTP/1.1's background read. Clearing the write deadline drops the previous request's on a
	// kept-alive HTTP/1.1 connection.
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{})
	rec := &recorder{ResponseWriter: w, rc: rc, status: http.StatusOK}
	req.Body = &progressReader{req.Body, rec}
	e, ok := r.routes[hostOnly(req.Host)]
	if !ok {
		e.name = "-" // the log schema's "no route"
	}
	// Deferred: ReverseProxy aborts a response that fails mid-body by panicking with
	// http.ErrAbortHandler; the request is still logged and counted, then the panic goes on.
	defer r.done(req, e.name, rec, start)
	if ok {
		e.h.ServeHTTP(rec, req)
	} else {
		http.NotFound(rec, req)
	}
}

func (r *Router) done(req *http.Request, route string, rec *recorder, start time.Time) {
	d := time.Since(start)
	r.metrics.Request(r.listener, route, req.Method, rec.status, rec.bytes, d)
	if r.access {
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
		// The wait for the headers is unbounded (ADR 0007); the body is not.
		ModifyResponse: func(res *http.Response) error {
			res.Body = newUpstreamBody(res.Body)
			return nil
		},
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

// progressReader arms the read deadline for each Read of the request body only, and counts its
// progress as the request's.
type progressReader struct {
	io.ReadCloser
	rec *recorder
}

func (p *progressReader) Read(b []byte) (int, error) {
	p.rec.rc.SetReadDeadline(time.Now().Add(ProgressTimeout))
	n, err := p.ReadCloser.Read(b)
	p.rec.rc.SetReadDeadline(time.Time{})
	if n > 0 && p.rec.writing.Load() {
		p.rec.push()
	}
	return n, err
}

type recorder struct {
	http.ResponseWriter
	rc      *http.ResponseController
	writing atomic.Bool // output began: the write deadline is armed
	status  int
	bytes   int64
}

// push moves the write deadline. HTTP/2 resets a stream whose deadline passes even between
// writes, so an upload still progressing pushes it too.
func (r *recorder) push() { r.rc.SetWriteDeadline(time.Now().Add(ProgressTimeout)) }

func (r *recorder) WriteHeader(code int) {
	r.writing.Store(true)
	r.push()
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.writing.Store(true)
	r.push()
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach Flush and Hijack (streaming, WebSocket upgrades).
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// upstreamBody closes the backend's response body when one Read waits ProgressTimeout, which
// aborts the response (the frontend deadlines cannot see a backend that stops sending).
type upstreamBody struct {
	io.ReadCloser
	t *time.Timer
}

func newUpstreamBody(b io.ReadCloser) *upstreamBody {
	t := time.AfterFunc(ProgressTimeout, func() { b.Close() })
	t.Stop()
	return &upstreamBody{b, t}
}

func (u *upstreamBody) Read(b []byte) (int, error) {
	u.t.Reset(ProgressTimeout)
	defer u.t.Stop()
	return u.ReadCloser.Read(b)
}

// upstreamConn cuts a write to a backend that consumes nothing for ProgressTimeout, such as an
// upload it stopped reading. Reads are left alone: the headers may take long.
type upstreamConn struct{ net.Conn }

func (c upstreamConn) Write(b []byte) (int, error) {
	c.SetWriteDeadline(time.Now().Add(ProgressTimeout))
	return c.Conn.Write(b)
}
