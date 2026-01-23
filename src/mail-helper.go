package liquidproxy

import (
	"bufio"
	"crypto/tls"
	"net"
)

// MailProxy handles IMAP and SMTP proxy connections
type MailProxy struct {
	// Protocol type (IMAP or SMTP)
	Protocol string

	// Listen port
	Port int

	// Default remote port if not specified
	DefaultRemotePort int

	// TLS config for upstream connections
	TLSConfig *tls.Config

	// Enable debug logging
	Debug bool
}

// MailConnection represents a single mail proxy connection
type MailConnection struct {
	id            string
	clientConn    net.Conn
	serverConn    net.Conn
	protocol      string
	targetServer  string
	realUsername  string
	authenticated bool
	tlsEnabled    bool
	reader        *bufio.Reader
	writer        *bufio.Writer
	serverReader  *bufio.Reader
	serverWriter  *bufio.Writer
	debug         bool
}
