package serve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func selfSigned(t *testing.T, host string) *tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestSNISelection(t *testing.T) {
	cfg := TLSConfig(map[string]*tls.Certificate{
		"a.example": selfSigned(t, "a.example"),
		"b.example": selfSigned(t, "b.example"),
	})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()

	for _, sni := range []string{"a.example", "B.EXAMPLE"} {
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("%s: %v", sni, err)
		}
		if got := c.ConnectionState().PeerCertificates[0].DNSNames[0]; got != "a.example" && sni == "a.example" || got != "b.example" && sni != "a.example" {
			t.Errorf("%s: served certificate for %s", sni, got)
		}
		c.Close()
	}
	for _, sni := range []string{"c.example", ""} {
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		if err == nil {
			c.Close()
			t.Errorf("sni %q: handshake succeeded, want failure", sni)
		} else if !strings.Contains(err.Error(), "unrecognized name") {
			t.Errorf("sni %q: %v, want an unrecognized_name alert", sni, err)
		}
	}
}
