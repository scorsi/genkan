package serve

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestConnectionCap(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := limit(raw, 1)
	defer ln.Close()

	first, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	second, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	held, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}

	accepted := make(chan struct{})
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
		close(accepted)
	}()
	select {
	case <-accepted:
		t.Fatal("second connection accepted above the cap")
	case <-time.After(100 * time.Millisecond):
	}
	held.Close()
	first.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("slot not released after Close")
	}
}

func TestHeaderDeadline(t *testing.T) {
	ReadHeaderTimeout = 100 * time.Millisecond
	defer func() { ReadHeaderTimeout = 10 * time.Second }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(http.NotFoundHandler(), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	go srv.Serve(ln)
	defer srv.Close()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection that sent nothing was not closed at the deadline")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("server kept the silent connection open")
	}
}
