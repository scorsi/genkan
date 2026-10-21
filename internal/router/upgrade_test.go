package router

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// R2: ReverseProxy needs the 101 body to remain an io.ReadWriteCloser.
func TestWebSocketRoundTrip(t *testing.T) {
	shortTimeout(t)
	finished := make(chan struct{})
	front, _, _ := proxied(t, func(w http.ResponseWriter, r *http.Request) {
		defer close(finished)
		c, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if r.Header.Get("Upgrade") != "websocket" || r.Header.Get("Sec-WebSocket-Key") != "dGhlIHNhbXBsZSBub25jZQ==" {
			t.Error("WebSocket handshake headers not forwarded")
			return
		}
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		if err := buf.Flush(); err != nil {
			t.Error(err)
			return
		}
		for range 2 {
			frame := make([]byte, 8)
			if _, err := io.ReadFull(buf, frame); err != nil {
				t.Error(err)
				return
			}
			if frame[0] != 0x81 || frame[1] != 0x82 || frame[6]^frame[2] != 'h' || frame[7]^frame[3] != 'i' {
				t.Errorf("invalid masked text frame: %x", frame)
				return
			}
			if _, err := c.Write([]byte{0x81, 2, 'h', 'i'}); err != nil {
				t.Error(err)
				return
			}
		}
	}, false)
	c, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		c.Close()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("WebSocket backend did not exit")
		}
	}()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: a.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	buf := bufio.NewReader(c)
	res, err := http.ReadResponse(buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusSwitchingProtocols || res.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("upgrade failed: %s, headers=%v", res.Status, res.Header)
	}
	for range 2 {
		// The tunnel is not subject to the HTTP body deadline between messages (ADR 0007).
		time.Sleep(2 * ProgressTimeout)
		if _, err := c.Write([]byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2}); err != nil {
			t.Fatal(err)
		}
		frame := make([]byte, 4)
		if _, err := io.ReadFull(buf, frame); err != nil || !bytes.Equal(frame, []byte{0x81, 2, 'h', 'i'}) {
			t.Fatalf("echo frame=%x, err=%v", frame, err)
		}
	}
}
