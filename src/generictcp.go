package liquidproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type GenericRedirectRule struct {
	Host string
	Port int
	SRV  string
}

type GenericTCPProxy struct {
	ListenPort int

	Rule []GenericRedirectRule

	// TLS config for upstream connections
	ClientTLSConfig *tls.Config

	ServerTLSConfig *tls.Config

	debug bool

	ServerCA tls.Certificate
}

type GTCPConnection struct {
	id         string
	clientConn net.Conn
	serverConn net.Conn
	listenPort int
	Rule       []GenericRedirectRule
	debug      bool
}

func loadGenericTCPRules() error {
	genericTCPFile := "generic-tcp.txt"

	if _, err := os.Stat(genericTCPFile); os.IsNotExist(err) {
		return nil
	}

	file, err := os.Open(genericTCPFile)
	if err != nil {
		return fmt.Errorf("failed to open generic-tcp file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	fromPort := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		if fromPort == 0 {
			fromPort, err = strconv.Atoi(line)
			if err != nil {
				log.Printf("Warning: Invalid port on line %d: %s", lineNum, line)
			}
			continue
		} else {

			slice := strings.Split(line, ":")

			if len(slice) < 2 {
				log.Printf("Warning: Invalid host:port combo on line %d: %s", lineNum, line)
				continue
			}

			host := slice[0]
			port, err := strconv.Atoi(slice[1])
			if err != nil {
				log.Printf("Warning: Invalid port on line %d: %s", lineNum, slice[2])
				continue
			}

			parts := strings.SplitN(host, ".", 3)
			srv := ""
			if len(parts) == 3 && strings.HasPrefix(parts[0], "_") && parts[1] == "_tcp" {
				srv = parts[0]
				host = parts[2]
			}

			rule := GenericRedirectRule{
				Host: host,
				Port: port,
				SRV:  srv,
			}

			genericTCPRedirectMutex.Lock()
			genericTCPRedirectRules[fromPort] = append(genericTCPRedirectRules[port], rule)
			genericTCPRedirectPorts[fromPort] = true
			genericTCPRedirectMutex.Unlock()
			fromPort = 0
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading generic-tcp file: %w", err)
	}

	if len(genericTCPRedirectPorts) == 0 {
		return fmt.Errorf("Got no redirect rules")
	}

	return nil
}

func genericTCPProxyMain(systemRoots *x509.CertPool, ca tls.Certificate, tlsServerConfig *tls.Config) {
	if err := loadGenericTCPRules(); err != nil {
		log.Fatalf("Error loading exclusion rules: %v", err)
	}

	ClientTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    systemRoots,
	}

	for listenPort, rule := range genericTCPRedirectRules {
		p := &GenericTCPProxy{
			ListenPort:      listenPort,
			Rule:            rule,
			ClientTLSConfig: ClientTLSConfig,
			ServerTLSConfig: tlsServerConfig,
			debug:           *debug,
			ServerCA:        ca,
		}
		if err := p.Start(); err != nil {
			log.Fatalf("Error: %s", err)
		}
	}

	if len(genericTCPRedirectPorts) != 0 {
		log.Printf("Generic TCP proxy started")
	}
}

// Start starts the mail proxy listener
func (p *GenericTCPProxy) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.ListenPort))
	if err != nil {
		return fmt.Errorf("failed to start proxy on port %d: %w", p.ListenPort, err)
	}

	go func() {
		for {
			conn, err := listener.Accept()

			if err != nil {
				if p.debug {
					log.Printf("%d proxy accept error: %v", p.ListenPort, err)
				}
				continue
			}

			go p.handleConnection(conn)
		}
	}()

	return nil
}

// handleConnection handles a single client connection
func (p *GenericTCPProxy) handleConnection(clientConn net.Conn) {
	// Check if connection is from localhost unless allow-remote-connections is set
	if *blockRemoteConnections {
		host, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
		if err != nil {
			if p.debug {
				log.Printf("[%d] Error parsing remote address: %v", p.ListenPort, err)
			}
			clientConn.Close()
			return
		}

		// Check if the connection is from localhost
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			if p.debug {
				log.Printf("[%d] Rejected non-localhost connection from %s", p.ListenPort, host)
			}
			clientConn.Close()
			return
		}
	}

	connID := fmt.Sprintf("%d-%p", p.ListenPort, clientConn)
	c := &GTCPConnection{
		id:         connID,
		clientConn: clientConn,
		debug:      p.debug,
		listenPort: p.ListenPort,
		Rule:       p.Rule,
	}

	if c.debug {
		log.Printf("[%s] New connection from %s", connID, clientConn.RemoteAddr())
	}

	err := c.connectToServer(p.ClientTLSConfig)
	if err != nil {
		log.Printf("[%s] Error when connecting to remote: %s", connID, err)
		clientConn.Close()
		return
	}
	p.handleData(c)
}

// connectToServer establishes connection to the real mail server
func (c *GTCPConnection) connectToServer(tlsConfig *tls.Config) error {
	rule := c.Rule[0]
	host := rule.Host
	port := rule.Port
	fallbackSN := ""
	if rule.SRV != "" {
		_, addrs, err := net.LookupSRV(rule.SRV, "tcp", host)
		if err == nil {
			fallbackSN = fmt.Sprintf("%s:%d", host, port)
			host = addrs[0].Target
			port = int(addrs[0].Port)
		}
	}
	// Add port if not specified
	server := host
	if !strings.Contains(server, ":") {
		server = fmt.Sprintf("%s:%d", server, port)
	}

	if c.debug {
		log.Printf("[%s] Connecting to %s", c.id, server)
	}

	var tlsConf *tls.Config
	if tlsConfig == nil {
		tlsConf = &tls.Config{
			ServerName: host,
		}
	} else {
		tlsConf = tlsConfig
		tlsConf.ServerName = host
	}

	conn, err := tls.Dial("tcp", server, tlsConf)
	if err != nil {
		if fallbackSN != "" {
			conn, err2 := tls.Dial("tcp", server, tlsConf)
			if err2 != nil {
				return fmt.Errorf("%s, %s", err, err2)
			}
			c.serverConn = conn
			return nil
		}
		return err
	}

	c.serverConn = conn

	return nil
}

func (p *GenericTCPProxy) handleData(c *GTCPConnection) {
	// Peek at the ClientHello to determine routing
	clientHello, err := peekClientHello(c.clientConn)
	if err != nil {
		log.Printf("[%s] Error on peeking handshake: %s", c.id, err)
		return
	}

	if clientHello.isModernClient && *blockModernConnections {
		return
	}

	var sConfig *tls.Config
	// Create TLS server config
	if p.ServerTLSConfig == nil {
		sConfig = new(tls.Config)
	} else {
		sConfig = p.ServerTLSConfig
	}
	//sConfig.Certificates = []tls.Certificate{sConfig.RootCAs}
	sConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &p.ServerCA, nil
	}

	// Create a connection that can replay the ClientHello
	var tlsConn *tls.Conn
	if clientHello != nil {
		// We have already read the ClientHello, so we need to create a special connection
		// that will replay it when the TLS handshake starts
		replayConn := &replayConn{
			Conn:   c.clientConn,
			buffer: bytes.NewBuffer(clientHello.raw),
		}
		tlsConn = tls.Server(replayConn, sConfig)
	} else {
		// No ClientHello was peeked, proceed normally
		tlsConn = tls.Server(c.clientConn, sConfig)
	}

	// Perform TLS handshake
	err = tlsConn.Handshake()
	if err != nil {
		log.Printf("[%s] Error on peeking handshake: %s", c.id, err)
		return
	}
	if c.debug {
		log.Printf("[%s] Handshake finish", c.id)
	}

	c.transparentProxy(tlsConn)
}

// transparentProxy switches to transparent proxy mode after authentication
func (c *GTCPConnection) transparentProxy(tlsConn *tls.Conn) {
	if c.debug {
		log.Printf("[%s] Switching to transparent proxy mode", c.id)
	}

	// Verify connections are established
	if tlsConn == nil {
		if c.debug {
			log.Printf("[%s] ERROR: clientConn is nil in transparentProxy", c.id)
		}
		return
	}
	if c.serverConn == nil {
		if c.debug {
			log.Printf("[%s] ERROR: serverConn is nil in transparentProxy", c.id)
		}
		return
	}

	errc := make(chan error, 2)

	go func() {
		_, err := io.Copy(tlsConn, c.serverConn)
		errc <- err
	}()

	go func() {
		_, err := io.Copy(c.serverConn, tlsConn)
		errc <- err
	}()

	err2 := <-errc

	if c.debug {
		log.Printf("[%s] Close starting", c.id)
	}

	tlsConn.CloseWrite()

	err1 := <-errc

	ignore := func(err error) bool {
		if err == nil {
			return true
		}
		s := err.Error()
		return strings.Contains(s, "use of closed network connection") ||
			strings.Contains(s, "protocol is shutdown") ||
			strings.Contains(s, "close_notify") ||
			strings.Contains(s, "i/o timeout") ||
			err == io.EOF
	}

	if !ignore(err1) {
		log.Printf("[%s] copy error: %v", c.id, err1)
	}
	if !ignore(err2) {
		log.Printf("[%s] copy error: %v", c.id, err2)
	}

	if c.debug {
		log.Printf("[%s] Goodbye!", c.id)
	}

	tlsConn.SetDeadline(time.Time{})
	c.serverConn.SetDeadline(time.Time{})

	tlsConn.Close()
	c.serverConn.Close()
}
