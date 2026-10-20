// Package metrics counts what genkan serves and writes it in the Prometheus text format
// (masu metric convention, ADR 0008). Hand-written: no client library (ADR 0005).
package metrics

import (
	"cmp"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Buckets of genkan_request_duration_seconds, fixed in code (metric convention).
var Buckets = []float64{0.01, 0.05, 0.25, 1, 5}

// methods is the closed set of the method label; anything else is "other".
var methods = []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE"}

type lr struct{ listener, route string }

type req struct {
	lr
	method, code string
}

type hist struct {
	counts []uint64 // per bucket, not cumulative
	count  uint64
	sum    float64
}

// Registry holds every series since process start; a reload never resets it.
type Registry struct {
	version string

	mu        sync.Mutex
	requests  map[req]uint64
	durations map[lr]*hist
	bytes     map[lr]uint64
	upstream  map[string]uint64 // by route
	handshake map[string]uint64 // by listener
	expiry    map[string]int64  // by certificate, replaced on each apply
}

func New(version string) *Registry {
	return &Registry{
		version:   version,
		requests:  map[req]uint64{},
		durations: map[lr]*hist{},
		bytes:     map[lr]uint64{},
		upstream:  map[string]uint64{},
		handshake: map[string]uint64{},
		expiry:    map[string]int64{},
	}
}

// Request records one completed request.
func (m *Registry) Request(listener, route, method string, status int, bytes int64, d time.Duration) {
	if !slices.Contains(methods, method) {
		method = "other"
	}
	k := lr{listener, route}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[req{k, method, strconv.Itoa(status/100) + "xx"}]++
	h := m.durations[k]
	if h == nil {
		h = &hist{counts: make([]uint64, len(Buckets))}
		m.durations[k] = h
	}
	s := d.Seconds()
	if i, _ := slices.BinarySearch(Buckets, s); i < len(Buckets) {
		h.counts[i]++
	}
	h.count++
	h.sum += s
	m.bytes[k] += uint64(bytes)
}

func (m *Registry) UpstreamError(route string) {
	m.mu.Lock()
	m.upstream[route]++
	m.mu.Unlock()
}

func (m *Registry) HandshakeError(listener string) {
	m.mu.Lock()
	m.handshake[listener]++
	m.mu.Unlock()
}

// SetCertificates replaces the expiry of every loaded certificate (Unix seconds of NotAfter).
func (m *Registry) SetCertificates(expiry map[string]int64) {
	m.mu.Lock()
	m.expiry = expiry
	m.mu.Unlock()
}

// ServeHTTP answers GET /metrics.
func (m *Registry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	m.Write(w)
}

// Write writes every family, series sorted so the output is stable.
func (m *Registry) Write(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	family(w, "genkan_build_info", "gauge", "Build of the running binary.")
	fmt.Fprintf(w, "genkan_build_info{version=%s} 1\n", q(m.version))

	family(w, "genkan_requests_total", "counter", "Completed HTTP requests.")
	for _, k := range sorted(m.requests, func(a, b req) int {
		return cmp.Or(cmpLR(a.lr, b.lr), strings.Compare(a.method, b.method), strings.Compare(a.code, b.code))
	}) {
		fmt.Fprintf(w, "genkan_requests_total{%s,method=%s,code=%s} %d\n", k.lr.labels(), q(k.method), q(k.code), m.requests[k])
	}

	family(w, "genkan_request_duration_seconds", "histogram", "Time from request start to the end of the response.")
	for _, k := range sorted(m.durations, cmpLR) {
		h, cum := m.durations[k], uint64(0)
		for i, b := range Buckets {
			cum += h.counts[i]
			fmt.Fprintf(w, "genkan_request_duration_seconds_bucket{%s,le=%s} %d\n", k.labels(), q(strconv.FormatFloat(b, 'g', -1, 64)), cum)
		}
		fmt.Fprintf(w, "genkan_request_duration_seconds_bucket{%s,le=\"+Inf\"} %d\n", k.labels(), h.count)
		fmt.Fprintf(w, "genkan_request_duration_seconds_sum{%s} %s\n", k.labels(), strconv.FormatFloat(h.sum, 'g', -1, 64))
		fmt.Fprintf(w, "genkan_request_duration_seconds_count{%s} %d\n", k.labels(), h.count)
	}

	family(w, "genkan_response_bytes_total", "counter", "Response body bytes sent.")
	for _, k := range sorted(m.bytes, cmpLR) {
		fmt.Fprintf(w, "genkan_response_bytes_total{%s} %d\n", k.labels(), m.bytes[k])
	}

	family(w, "genkan_upstream_errors_total", "counter", "Requests answered 502 because the backend failed before the response started.")
	for _, r := range sorted(m.upstream, strings.Compare) {
		fmt.Fprintf(w, "genkan_upstream_errors_total{route=%s} %d\n", q(r), m.upstream[r])
	}

	family(w, "genkan_tls_handshake_errors_total", "counter", "Failed TLS handshakes.")
	for _, l := range sorted(m.handshake, strings.Compare) {
		fmt.Fprintf(w, "genkan_tls_handshake_errors_total{listener=%s} %d\n", q(l), m.handshake[l])
	}

	family(w, "genkan_certificate_expiry_timestamp_seconds", "gauge", "NotAfter of each loaded certificate's leaf.")
	for _, c := range sorted(m.expiry, strings.Compare) {
		fmt.Fprintf(w, "genkan_certificate_expiry_timestamp_seconds{certificate=%s} %d\n", q(c), m.expiry[c])
	}
}

func family(w io.Writer, name, typ, help string) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func (k lr) labels() string { return "listener=" + q(k.listener) + ",route=" + q(k.route) }

func cmpLR(a, b lr) int {
	return cmp.Or(strings.Compare(a.listener, b.listener), strings.Compare(a.route, b.route))
}

// q quotes a label value with the exposition format's three escapes.
func q(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s) + `"`
}

func sorted[K comparable, V any](m map[K]V, less func(a, b K) int) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, less)
	return keys
}
