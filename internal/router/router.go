// Package router routes HTTP requests by Host and logs them.
package router

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"
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
		return (&net.Dialer{Timeout: DialTimeout}).DialContext(ctx, network, addr)
	},
	MaxIdleConnsPerHost: 32,
	IdleConnTimeout:     90 * time.Second,
}

// Router serves one listener: it picks the route by Host and writes one access record per request.
type Router struct {
	listener string
	log      *slog.Logger
	access   bool
	routes   map[string]entry
}

type entry struct {
	name string
	h    http.Handler
}

func New(listener string, log *slog.Logger, access bool) *Router {
	return &Router{listener: listener, log: log, access: access, routes: map[string]entry{}}
}

// Handle serves host (lowercase, no port) with h. route is the name used in logs.
func (r *Router) Handle(host, route string, h http.Handler) {
	r.routes[host] = entry{route, h}
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	// Idle-based deadlines: pushed on every Read of the body and every Write of the response, so
	// a stalled transfer is cut while a slow continuous one passes (ADR 0007).
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(start.Add(ProgressTimeout))
	rc.SetWriteDeadline(start.Add(ProgressTimeout))
	req.Body = &progressReader{req.Body, rc}
	rec := &recorder{ResponseWriter: w, rc: rc, status: http.StatusOK}
	e, ok := r.routes[hostOnly(req.Host)]
	if ok {
		e.h.ServeHTTP(rec, req)
	} else {
		http.NotFound(rec, req)
	}
	if r.access {
		r.log.Info("request",
			"listener", r.listener,
			"route", e.name,
			"client", hostOnly(req.RemoteAddr),
			"method", req.Method,
			"host", req.Host,
			"path", req.URL.Path,
			"status", rec.status,
			"bytes", rec.bytes,
			"duration", time.Since(start),
			"user_agent", req.UserAgent(),
		)
	}
}

// Proxy forwards to backend, keeping the client's Host and overwriting X-Forwarded-For, -Host and
// -Proto with values genkan trusts (ReverseProxy strips the client's copies before Rewrite runs).
func Proxy(backend *url.URL, log *slog.Logger) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(backend)
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
		Transport: transport,
		ErrorLog:  slog.NewLogLogger(log.Handler(), slog.LevelError),
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

type progressReader struct {
	io.ReadCloser
	rc *http.ResponseController
}

func (p *progressReader) Read(b []byte) (int, error) {
	p.rc.SetReadDeadline(time.Now().Add(ProgressTimeout))
	return p.ReadCloser.Read(b)
}

type recorder struct {
	http.ResponseWriter
	rc     *http.ResponseController
	status int
	bytes  int64
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.rc.SetWriteDeadline(time.Now().Add(ProgressTimeout))
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach Flush and Hijack (streaming, WebSocket upgrades).
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
