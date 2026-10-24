package serve

import (
	"net"
	"sync"
)

// MaxConns is the cap on concurrent connections per listener (ADR 0007).
const MaxConns = 4096

// limitListener stops calling Accept above the cap; the kernel backlog absorbs the excess.
type limitListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

func limit(ln net.Listener, max int) *limitListener {
	return &limitListener{Listener: ln, slots: make(chan struct{}, max), done: make(chan struct{})}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitConn{Conn: c, slots: l.slots}, nil
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func (c *limitConn) Close() error {
	c.once.Do(func() { <-c.slots })
	return c.Conn.Close()
}

// CloseWrite half-closes the connection for passthrough (ADR 0007), keeping the slot.
func (c *limitConn) CloseWrite() error { return closeWrite(c.Conn) }
