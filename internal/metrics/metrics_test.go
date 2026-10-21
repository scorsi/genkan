package metrics

import (
	"strings"
	"testing"
	"time"
)

func TestExposition(t *testing.T) {
	m := New("1.2.3")
	m.Request("edge", "forgejo", "GET", 200, 100, 30*time.Millisecond)
	m.Request("edge", "forgejo", "GET", 204, 0, 2*time.Second)
	m.Request("edge", "forgejo", "BREW", 404, 9, time.Millisecond)
	m.Request("edge", "-", "GET", 404, 19, 10*time.Millisecond) // on a bound: le is inclusive
	m.UpstreamError("forgejo")
	m.HandshakeError("edge")
	m.SetCertificates(map[string]int64{"edge": 1799020800, `we"ird`: 1})

	var out strings.Builder
	m.Write(&out)
	want := `# HELP genkan_build_info Build of the running binary.
# TYPE genkan_build_info gauge
genkan_build_info{version="1.2.3"} 1
# HELP genkan_requests_total Completed HTTP requests.
# TYPE genkan_requests_total counter
genkan_requests_total{listener="edge",route="-",method="GET",code="4xx"} 1
genkan_requests_total{listener="edge",route="forgejo",method="GET",code="2xx"} 2
genkan_requests_total{listener="edge",route="forgejo",method="other",code="4xx"} 1
# HELP genkan_request_duration_seconds Time from request start to the end of the response.
# TYPE genkan_request_duration_seconds histogram
genkan_request_duration_seconds_bucket{listener="edge",route="-",le="0.01"} 1
genkan_request_duration_seconds_bucket{listener="edge",route="-",le="0.05"} 1
genkan_request_duration_seconds_bucket{listener="edge",route="-",le="0.25"} 1
genkan_request_duration_seconds_bucket{listener="edge",route="-",le="1"} 1
genkan_request_duration_seconds_bucket{listener="edge",route="-",le="5"} 1
genkan_request_duration_seconds_bucket{listener="edge",route="-",le="+Inf"} 1
genkan_request_duration_seconds_sum{listener="edge",route="-"} 0.01
genkan_request_duration_seconds_count{listener="edge",route="-"} 1
genkan_request_duration_seconds_bucket{listener="edge",route="forgejo",le="0.01"} 1
genkan_request_duration_seconds_bucket{listener="edge",route="forgejo",le="0.05"} 2
genkan_request_duration_seconds_bucket{listener="edge",route="forgejo",le="0.25"} 2
genkan_request_duration_seconds_bucket{listener="edge",route="forgejo",le="1"} 2
genkan_request_duration_seconds_bucket{listener="edge",route="forgejo",le="5"} 3
genkan_request_duration_seconds_bucket{listener="edge",route="forgejo",le="+Inf"} 3
genkan_request_duration_seconds_sum{listener="edge",route="forgejo"} 2.0309999999999997
genkan_request_duration_seconds_count{listener="edge",route="forgejo"} 3
# HELP genkan_response_bytes_total Response body bytes sent.
# TYPE genkan_response_bytes_total counter
genkan_response_bytes_total{listener="edge",route="-"} 19
genkan_response_bytes_total{listener="edge",route="forgejo"} 109
# HELP genkan_upstream_errors_total Requests answered 502 because the backend failed before the response started.
# TYPE genkan_upstream_errors_total counter
genkan_upstream_errors_total{route="forgejo"} 1
# HELP genkan_tls_handshake_errors_total Failed TLS handshakes.
# TYPE genkan_tls_handshake_errors_total counter
genkan_tls_handshake_errors_total{listener="edge"} 1
# HELP genkan_certificate_expiry_timestamp_seconds NotAfter of each loaded certificate's leaf.
# TYPE genkan_certificate_expiry_timestamp_seconds gauge
genkan_certificate_expiry_timestamp_seconds{certificate="edge"} 1799020800
genkan_certificate_expiry_timestamp_seconds{certificate="we\"ird"} 1
`
	if out.String() != want {
		t.Errorf("got:\n%s", out.String())
	}
}

// G6: a scrape whose client stops reading does not hold the lock request accounting needs.
func TestBlockedScrapeDoesNotBlockAccounting(t *testing.T) {
	m := New("test")
	unblock := make(chan struct{})
	defer close(unblock)
	go m.Write(blockingWriter(unblock))
	time.Sleep(50 * time.Millisecond) // let Write reach the writer
	done := make(chan struct{})
	go func() {
		m.Request("lan", "a", "GET", 200, 1, time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("request accounting blocked by a stalled scrape")
	}
}

type blockingWriter chan struct{}

func (w blockingWriter) Write(p []byte) (int, error) {
	<-w
	return len(p), nil
}
