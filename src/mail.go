package liquidproxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
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

func mailMain(systemRoots *x509.CertPool) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    systemRoots,
	}

	// Start IMAP proxy
	if !*disableIMAP {
		imapProxy := &MailProxy{
			Protocol:          "IMAP",
			Port:              *imapPort,
			DefaultRemotePort: 993,
			TLSConfig:         tlsConfig,
			Debug:             *debug,
		}
		if err := imapProxy.Start(); err != nil {
			log.Fatal("Failed to start IMAP proxy:", err)
		}
	}

	// Start SMTP proxy
	if !*disableSMTP {
		smtpProxy := &MailProxy{
			Protocol:          "SMTP",
			Port:              *smtpPort,
			DefaultRemotePort: 587,
			TLSConfig:         tlsConfig,
			Debug:             *debug,
		}
		if err := smtpProxy.Start(); err != nil {
			log.Fatal("Failed to start SMTP proxy:", err)
		}
	}

	// Print single startup message
	if !*disableIMAP && !*disableSMTP {
		log.Printf("Mail Proxy started (IMAP:%d, SMTP:%d)", *imapPort, *smtpPort)
	} else if !*disableIMAP {
		log.Printf("Mail Proxy started (IMAP:%d)", *imapPort)
	} else if !*disableSMTP {
		log.Printf("Mail Proxy started (SMTP:%d)", *smtpPort)
	}
}

// Start starts the mail proxy listener
func (mp *MailProxy) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", mp.Port))
	if err != nil {
		return fmt.Errorf("failed to start %s proxy on port %d: %w", mp.Protocol, mp.Port, err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if mp.Debug {
					log.Printf("%s proxy accept error: %v", mp.Protocol, err)
				}
				continue
			}

			go mp.handleConnection(conn)
		}
	}()

	return nil
}

// handleConnection handles a single client connection
func (mp *MailProxy) handleConnection(clientConn net.Conn) {
	// Check if connection is from localhost unless allow-remote-connections is set
	if *blockRemoteConnections {
		host, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
		if err != nil {
			if mp.Debug {
				log.Printf("Error parsing remote address: %v", err)
			}
			clientConn.Close()
			return
		}

		// Check if the connection is from localhost
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			if mp.Debug {
				log.Printf("Rejected non-localhost connection from %s", host)
			}
			clientConn.Close()
			return
		}
	}

	connID := fmt.Sprintf("%s-%p", mp.Protocol, clientConn)
	mc := &MailConnection{
		id:         connID,
		clientConn: clientConn,
		protocol:   mp.Protocol,
		reader:     bufio.NewReader(clientConn),
		writer:     bufio.NewWriter(clientConn),
		debug:      mp.Debug,
	}

	defer mc.Close()

	if mc.debug {
		log.Printf("[%s] New %s connection from %s", connID, mp.Protocol, clientConn.RemoteAddr())
	}

	// Handle based on protocol
	if mp.Protocol == "IMAP" {
		mp.handleIMAP(mc)
	} else if mp.Protocol == "SMTP" {
		mp.handleSMTP(mc)
	}
}

// parseUsername extracts the real username and target server from the proxy username
func (mc *MailConnection) parseUsername(username string) error {
	// Username format: realuser@domain@server
	lastAt := strings.LastIndex(username, "@")
	if lastAt == -1 || lastAt == 0 || lastAt == len(username)-1 {
		return fmt.Errorf("invalid username format, use: user@domain@server")
	}

	un := username[:lastAt]
	if strings.HasSuffix(un, "@") {
		mc.realUsername = strings.TrimRight(un, "@")
	} else {
		// john@example.com. correct answer is john@@example.com
		return fmt.Errorf("Get off of my server :(")
	}
	mc.targetServer = username[lastAt+1:]

	// Validate server name
	if mc.targetServer == "" || mc.targetServer == "localhost" {
		return fmt.Errorf("invalid target server")
	}

	if mc.debug {
		log.Printf("[%s] Parsed username: %s -> server: %s", mc.id, mc.realUsername, mc.targetServer)
	}
	return nil
}

// connectToServer establishes connection to the real mail server
func (mc *MailConnection) connectToServer(tlsConfig *tls.Config, port int) error {
	// Add port if not specified
	server := mc.targetServer
	if !strings.Contains(server, ":") {
		server = fmt.Sprintf("%s:%d", server, port)
	}

	if mc.debug {
		log.Printf("[%s] Connecting to %s", mc.id, server)
	}

	// For SMTP on port 465, use direct TLS
	if mc.protocol == "SMTP" && port == 465 {
		var tlsConf *tls.Config
		if tlsConfig == nil {
			tlsConf = &tls.Config{
				ServerName: mc.targetServer,
			}
		} else {
			tlsConf = tlsConfig
			tlsConf.ServerName = mc.targetServer
		}

		conn, err := tls.Dial("tcp", server, tlsConf)
		if err != nil {
			return err
		}

		mc.serverConn = conn
		mc.tlsEnabled = true
	} else {
		// For IMAP and SMTP on 587, start with plain connection
		conn, err := net.Dial("tcp", server)
		if err != nil {
			return err
		}

		mc.serverConn = conn

		// For IMAP, always upgrade to TLS immediately
		if mc.protocol == "IMAP" {
			var tlsConf *tls.Config
			if tlsConfig == nil {
				tlsConf = &tls.Config{
					ServerName: mc.targetServer,
				}
			} else {
				tlsConf = tlsConfig
				tlsConf.ServerName = mc.targetServer
			}

			tlsConn := tls.Client(conn, tlsConf)
			if err := tlsConn.Handshake(); err != nil {
				conn.Close()
				return fmt.Errorf("TLS handshake failed: %w", err)
			}

			mc.serverConn = tlsConn
			mc.tlsEnabled = true
		}
	}

	mc.serverReader = bufio.NewReader(mc.serverConn)
	mc.serverWriter = bufio.NewWriter(mc.serverConn)

	return nil
}

// transparentProxy switches to transparent proxy mode after authentication
func (mc *MailConnection) transparentProxy() {
	if mc.debug {
		log.Printf("[%s] Switching to transparent proxy mode", mc.id)
	}

	// Verify connections are established
	if mc.clientConn == nil {
		if mc.debug {
			log.Printf("[%s] ERROR: clientConn is nil in transparentProxy", mc.id)
		}
		return
	}
	if mc.serverConn == nil {
		if mc.debug {
			log.Printf("[%s] ERROR: serverConn is nil in transparentProxy", mc.id)
		}
		return
	}

	// For SMTP, we need to rewrite MAIL FROM commands
	if mc.protocol == "SMTP" {
		mc.transparentSMTPProxy()
		return
	}

	// For IMAP, use simple transparent proxy
	done := make(chan bool, 2)

	// Client to server
	go func() {
		io.Copy(mc.serverConn, mc.clientConn)
		done <- true
	}()

	// Server to client
	go func() {
		io.Copy(mc.clientConn, mc.serverConn)
		done <- true
	}()

	// Wait for either direction to complete
	<-done

	// Close connections
	mc.Close()
}

// Close closes all connections
func (mc *MailConnection) Close() {
	if mc.clientConn != nil {
		mc.clientConn.Close()
	}
	if mc.serverConn != nil {
		mc.serverConn.Close()
	}
}
