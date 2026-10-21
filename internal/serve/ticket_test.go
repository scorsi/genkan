package serve

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// sessionTicket obtains a real TLS 1.2 server ticket without opening a socket.
// TLS 1.3 needs buffered I/O for its handshake flights; reload_test.go covers it over TCP.
func sessionTicket(t *testing.T, cfg *tls.Config, cache tls.ClientSessionCache) ([]byte, tls.ConnectionState) {
	t.Helper()
	cfg = cfg.Clone()
	var ticket []byte
	wrap := cfg.WrapSession
	cfg.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
		var err error
		ticket, err = wrap(cs, ss)
		return ticket, err
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(5 * time.Second))
	b.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() {
		server := tls.Server(a, cfg)
		_, err := server.Write([]byte{1})
		done <- err
	}()
	client := tls.Client(b, &tls.Config{
		ServerName: "a.example", InsecureSkipVerify: true,
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		ClientSessionCache: cache, NextProtos: []string{"h2"},
	})
	if _, err := io.ReadFull(client, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(ticket) == 0 || client.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("handshake did not issue a ticket and negotiate h2")
	}
	return ticket, client.ConnectionState()
}

func TestSessionTicketBinding(t *testing.T) {
	now := time.Now()
	tickets := &tls.Config{Time: func() time.Time { return now }}
	cert := selfSigned(t, "a.example")
	hosts := map[string]*tls.Certificate{"a.example": cert, "b.example": cert}
	identity, _ := sessionTicket(t, TLSConfig(hosts, tickets), tls.NewLRUClientSessionCache(1))
	cs := tls.ConnectionState{ServerName: "a.example"}
	check := func(name string, cfg *tls.Config, ticket []byte, sni string, want bool) {
		t.Helper()
		ss, err := cfg.UnwrapSession(ticket, tls.ConnectionState{ServerName: sni})
		if err != nil || (ss != nil) != want {
			t.Errorf("%s: accepted=%v, err=%v, want %v", name, ss != nil, err, want)
		}
	}
	reloaded := TLSConfig(hosts, tickets)
	check("unchanged", reloaded, identity, "a.example", true)
	check("case insensitive", reloaded, identity, "A.EXAMPLE", true)
	check("other name, same certificate", reloaded, identity, "b.example", false)
	check("removed name", TLSConfig(nil, tickets), identity, "a.example", false)
	check("absent SNI", reloaded, identity, "", false)
	check("changed certificate", TLSConfig(map[string]*tls.Certificate{"a.example": selfSigned(t, "a.example")}, tickets), identity, "a.example", false)
	check("different listener keys", TLSConfig(hosts, new(tls.Config)), identity, "a.example", false)
	check("malformed ticket", reloaded, []byte("garbage"), "a.example", false)
	tampered := append([]byte(nil), identity...)
	tampered[len(tampered)-1] ^= 1
	check("tampered ticket", reloaded, tampered, "a.example", false)

	ss, err := tickets.DecryptTicket(identity, cs)
	if err != nil || ss == nil {
		t.Fatalf("decrypt own ticket: %v", err)
	}
	for _, extra := range [][][]byte{nil, {[]byte("genkan/session/v1\x00garbage")}} {
		ss.Extra = extra
		unbound, err := tickets.EncryptTicket(cs, ss)
		if err != nil {
			t.Fatal(err)
		}
		check("missing or invalid binding", reloaded, unbound, "a.example", false)
	}

	// Exercise Go's automatic rotation, not a custom key scheduler.
	now = now.Add(25 * time.Hour)
	check("previous key after rotation", reloaded, identity, "a.example", true)
	now = now.Add(7 * 24 * time.Hour)
	check("expired key", reloaded, identity, "a.example", false)
}

func TestSessionResumptionInMemory(t *testing.T) {
	tickets := new(tls.Config)
	hosts := map[string]*tls.Certificate{"a.example": selfSigned(t, "a.example")}
	cache := tls.NewLRUClientSessionCache(1)
	if _, cs := sessionTicket(t, TLSConfig(hosts, tickets), cache); cs.DidResume {
		t.Fatal("first handshake resumed")
	}
	if _, cs := sessionTicket(t, TLSConfig(hosts, tickets), cache); !cs.DidResume {
		t.Fatal("same certificate did not resume with a new configuration")
	}
	hosts["a.example"] = selfSigned(t, "a.example")
	if _, cs := sessionTicket(t, TLSConfig(hosts, tickets), cache); cs.DidResume {
		t.Fatal("changed certificate resumed")
	}
}
