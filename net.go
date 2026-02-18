package main

import (
	"bytes"
	"io"
	"net"
	"sync"
)

// singleUseListener implements net.Listener for a single connection
type singleUseListener struct {
	conn   net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *singleUseListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, io.EOF
	default:
		l.once.Do(func() {
			close(l.closed)
		})
		return l.conn, nil
	}
}

func (l *singleUseListener) Close() error {
	select {
	case <-l.closed:
		return nil
	default:
		close(l.closed)
		return nil
	}
}

func (l *singleUseListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// replayConn is a net.Conn wrapper that replays buffered data before reading from the underlying connection
type replayConn struct {
	net.Conn
	buffer *bytes.Buffer
}

func (c *replayConn) Read(b []byte) (int, error) {
	// First, read from the buffer if there's data
	if c.buffer.Len() > 0 {
		return c.buffer.Read(b)
	}
	// Then read from the underlying connection
	return c.Conn.Read(b)
}
