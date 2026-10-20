// Package serve binds the listeners of a config, swaps them on reload, and runs until the context ends.
package serve

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/scorsi/genkan/internal/cert"
	"github.com/scorsi/genkan/internal/config"
	"github.com/scorsi/genkan/internal/logging"
	"github.com/scorsi/genkan/internal/metrics"
	"github.com/scorsi/genkan/internal/router"
)

// Limits of ADR 0007. Variables rather than constants so tests can shrink them.
var (
	// ReadHeaderTimeout bounds the TLS handshake plus the request headers.
	ReadHeaderTimeout = 10 * time.Second
	// IdleTimeout closes a keep-alive connection idle between requests.
	IdleTimeout = 120 * time.Second
)

// TLSConfig picks the certificate by SNI from the map hosts returns at handshake time. An unknown
// or absent server name returns no certificate, which crypto/tls answers with an unrecognized_name
// alert.
func TLSConfig(hosts func() map[string]*tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return hosts()[strings.ToLower(hello.ServerName)], nil
		},
	}
}

// newServer sends net/http's own error lines to errorLog: they must be schema lines too.
func newServer(h http.Handler, tlsConfig *tls.Config, errorLog *log.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: ReadHeaderTimeout,
		IdleTimeout:       IdleTimeout,
		ErrorLog:          errorLog,
	}
}

// handshakeError is how net/http reports a failed TLS handshake; it offers no other hook.
const handshakeError = "http: TLS handshake error"

// state is what one listener serves; a reload replaces it whole.
type state struct {
	listener string
	rt       *router.Router
	hosts    map[string]*tls.Certificate
}

// slot is one bound address. It survives reloads as long as some listener keeps its addr.
type slot struct {
	ln    net.Listener
	srv   *http.Server
	state atomic.Pointer[state]
}

// Server holds the bound addresses and the routing state served on each.
type Server struct {
	log     *slog.Logger
	level   *slog.LevelVar
	metrics *metrics.Registry
	slots   map[string]*slot // by listener addr
}

// New returns a Server with nothing bound. Apply sets level from each config's log.level.
func New(log *slog.Logger, level *slog.LevelVar, m *metrics.Registry) *Server {
	return &Server{log: log, level: level, metrics: m, slots: map[string]*slot{}}
}

// Apply loads cfg's certificates, builds every listener's routes and binds the addresses not yet
// bound, then swaps all listeners at once and closes the addresses cfg dropped. An error leaves
// the running config untouched (ADR 0003).
func (s *Server) Apply(cfg *config.Config) error {
	certs, err := cert.Load(cfg.Certificates)
	if err != nil {
		return err
	}

	states := map[string]*state{}
	for _, l := range cfg.Listeners {
		st, err := s.build(l.Name, cfg, certs)
		if err != nil {
			return err
		}
		states[l.Addr] = st
	}
	fresh := map[string]*slot{}
	for _, l := range cfg.Listeners {
		if s.slots[l.Addr] != nil {
			continue
		}
		ln, err := net.Listen("tcp", l.Addr)
		if err != nil {
			for _, sl := range fresh {
				sl.ln.Close()
			}
			return fmt.Errorf("listener %q: %w", l.Name, err)
		}
		fresh[l.Addr] = &slot{ln: ln}
	}

	slots := map[string]*slot{}
	for _, l := range cfg.Listeners {
		sl := s.slots[l.Addr]
		if sl == nil {
			sl = fresh[l.Addr]
		}
		sl.state.Store(states[l.Addr])
		slots[l.Addr] = sl
		s.log.Info("", "event", "listening", "listener", l.Name, "addr", sl.ln.Addr().String(), "hosts", len(states[l.Addr].hosts))
	}
	for _, sl := range fresh {
		s.start(sl)
	}
	for addr, sl := range s.slots {
		if slots[addr] == nil {
			sl.srv.Close() // no draining in v0 (ADR 0003): in-flight connections are dropped
			s.log.Info("", "event", "listener-closed", "addr", addr)
		}
	}
	s.slots = slots
	s.level.UnmarshalText([]byte(cfg.Log.Level))
	s.metrics.SetCertificates(certs.Expiry())
	return nil
}

func (s *Server) build(listener string, cfg *config.Config, certs cert.Files) (*state, error) {
	st := &state{listener: listener, rt: router.New(listener, s.log, cfg.Log.Access, s.metrics), hosts: map[string]*tls.Certificate{}}
	for _, r := range cfg.Routes {
		if !slices.Contains(r.Listeners, listener) {
			continue
		}
		var h http.Handler
		switch r.Type {
		case "http":
			backend, err := url.Parse(r.Backend)
			if err != nil {
				return nil, fmt.Errorf("route %q: %w", r.Name, err)
			}
			h = router.Proxy(backend, listener, r.Name, s.log, s.metrics)
		case "static":
			h = router.Static(r.Root)
		}
		for _, host := range r.Hosts {
			st.rt.Handle(host, r.Name, h)
			st.hosts[host] = certs[r.Certificate]
			if !certs.Covers(r.Certificate, host) {
				s.log.Warn("certificate does not cover host", "event", "certificate-mismatch", "certificate", r.Certificate, "host", host, "route", r.Name)
			}
		}
	}
	return st, nil
}

// start serves sl with whatever state it holds at each request and each handshake.
func (s *Server) start(sl *slot) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sl.state.Load().rt.ServeHTTP(w, r) })
	errorLog := logging.Std(s.log, func(line string) string {
		if strings.HasPrefix(line, handshakeError) {
			s.metrics.HandshakeError(sl.state.Load().listener)
			return "tls-handshake-error"
		}
		return "http-error"
	})
	sl.srv = newServer(h, TLSConfig(func() map[string]*tls.Certificate { return sl.state.Load().hosts }), errorLog)
	go func() {
		if err := sl.srv.ServeTLS(limit(sl.ln, MaxConns), "", ""); !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("", "event", "listener-stopped", "addr", sl.ln.Addr().String(), "err", err.Error())
		}
	}()
}

// Shutdown stops every listener, giving in-flight requests up to timeout.
func (s *Server) Shutdown(timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for _, sl := range s.slots {
		sl.srv.Shutdown(ctx)
	}
}

// Run serves cfg until ctx is done. SIGHUP re-reads path and applies it; a config that fails to
// load or apply is logged and the running one stays (ADR 0003). The metrics listener is bound once,
// at start: a reload does not move it (ADR 0008). READY=1 is sent to systemd once every listener
// is bound.
func Run(ctx context.Context, path string, cfg *config.Config, log *slog.Logger, level *slog.LevelVar, m *metrics.Registry) error {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	s := New(log, level, m)
	if err := s.Apply(cfg); err != nil {
		return err
	}
	defer s.Shutdown(5 * time.Second)
	if cfg.Metrics.Listen != "" {
		stop, err := serveMetrics(cfg.Metrics.Listen, log, m)
		if err != nil {
			return err
		}
		defer stop()
	}
	if err := notify("READY=1"); err != nil {
		log.Warn("", "event", "sd-notify-failed", "err", err.Error())
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-hup:
			cfg, warnings, err := config.Load(path)
			for _, w := range warnings {
				log.Warn("", "event", "config-warning", "err", w)
			}
			if err == nil {
				err = s.Apply(cfg)
			}
			if err != nil {
				log.Error("keeping the running config", "event", "reload-failed", "err", err.Error())
				continue
			}
			log.Info("", "event", "reloaded", "path", path)
		}
	}
}

// serveMetrics answers GET /metrics on addr (loopback, checked by config) until stop is called.
func serveMetrics(addr string, log *slog.Logger, m *metrics.Registry) (stop func(), err error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("metrics.listen: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", m)
	srv := newServer(mux, nil, logging.Std(log, func(string) string { return "http-error" }))
	go func() {
		if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			log.Error("", "event", "listener-stopped", "addr", addr, "err", err.Error())
		}
	}()
	log.Info("", "event", "metrics-listening", "addr", ln.Addr().String())
	return func() { srv.Close() }, nil
}

// notify writes state to systemd's NOTIFY_SOCKET; a no-op outside a Type=notify unit. Go maps a
// leading '@' to Linux's abstract namespace.
func notify(state string) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte(state))
	return err
}
