// Package serve binds the listeners of a config and runs them until the context ends.
package serve

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/scorsi/genkan/internal/cert"
	"github.com/scorsi/genkan/internal/config"
	"github.com/scorsi/genkan/internal/router"
)

// Limits of ADR 0007. Variables rather than constants so tests can shrink them.
var (
	// ReadHeaderTimeout bounds the TLS handshake plus the request headers.
	ReadHeaderTimeout = 10 * time.Second
	// IdleTimeout closes a keep-alive connection idle between requests.
	IdleTimeout = 120 * time.Second
)

// TLSConfig picks the certificate by SNI. An unknown or absent server name returns no certificate,
// which crypto/tls answers with an unrecognized_name alert.
func TLSConfig(hosts map[string]*tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return hosts[strings.ToLower(hello.ServerName)], nil
		},
	}
}

func newServer(h http.Handler, tlsConfig *tls.Config, log *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: ReadHeaderTimeout,
		IdleTimeout:       IdleTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelError),
	}
}

// Run binds every listener (fail fast on the first error), serves until ctx is done, then shuts
// down. v0.1: no SIGHUP handling, restart to apply a new config.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	certs, err := cert.Load(cfg.Certificates)
	if err != nil {
		return err
	}
	var servers []*http.Server
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, s := range servers {
			s.Shutdown(shutdown)
		}
	}()
	for _, l := range cfg.Listeners {
		rt := router.New(l.Name, log, cfg.Log.Access)
		hosts := map[string]*tls.Certificate{}
		for _, r := range cfg.Routes {
			if !contains(r.Listeners, l.Name) {
				continue
			}
			backend, err := url.Parse(r.Backend)
			if err != nil {
				return fmt.Errorf("route %q: %w", r.Name, err)
			}
			h := router.Proxy(backend, log)
			for _, host := range r.Hosts {
				rt.Handle(host, r.Name, h)
				hosts[host] = certs[r.Certificate]
				if !certs.Covers(r.Certificate, host) {
					log.Warn("certificate does not cover host", "certificate", r.Certificate, "host", host, "route", r.Name)
				}
			}
		}
		ln, err := net.Listen("tcp", l.Addr)
		if err != nil {
			return fmt.Errorf("listener %q: %w", l.Name, err)
		}
		srv := newServer(rt, TLSConfig(hosts), log)
		servers = append(servers, srv)
		go func() {
			if err := srv.ServeTLS(limit(ln, MaxConns), "", ""); !errors.Is(err, http.ErrServerClosed) {
				log.Error("listener stopped", "listener", l.Name, "err", err)
			}
		}()
		log.Info("listening", "listener", l.Name, "addr", ln.Addr().String(), "hosts", len(hosts))
	}
	<-ctx.Done()
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
