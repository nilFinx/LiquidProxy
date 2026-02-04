package liquidproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

type XMPPProxy struct {
	Port int

	// Default remote port if not specified
	DefaultRemotePort int

	// TLS config for upstream connections
	TLSConfig *tls.Config

	ServerTLSConfig *tls.Config

	// Enable debug logging
	Debug bool

	ServerCA tls.Certificate
}

type XMPPHello struct {
	To string `xml:"to,attr"`
}

type XMPPConnection struct {
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

func xmppMain(systemRoots *x509.CertPool, ca tls.Certificate, tlsServerConfig *tls.Config) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    systemRoots,
	}

	if *enableXMPP {
		proxy := &XMPPProxy{
			Port:              *xmppPort,
			DefaultRemotePort: 5223,
			TLSConfig:         tlsConfig,
			ServerTLSConfig:   tlsServerConfig,
			Debug:             *debug,
			ServerCA:          ca,
		}
		if err := proxy.Start(); err != nil {
			log.Fatal("Failed to start XMPP proxy:", err)
		}
	}

	log.Printf("XMPP Proxy started (%d)", *xmppPort)
}

// Start starts the mail proxy listener
func (p *XMPPProxy) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.Port))
	if err != nil {
		return fmt.Errorf("failed to start XMPP proxy on port %d: %w", p.Port, err)
	}

	go func() {
		for {
			conn, err := listener.Accept()

			if err != nil {
				if p.Debug {
					log.Printf("XMPP proxy accept error: %v", err)
				}
				continue
			}

			go p.handleConnection(conn)
		}
	}()

	return nil
}

// handleConnection handles a single client connection
func (p *XMPPProxy) handleConnection(clientConn net.Conn) {
	// Check if connection is from localhost unless allow-remote-connections is set
	if *blockRemoteConnections {
		host, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
		if err != nil {
			if p.Debug {
				log.Printf("Error parsing remote address: %v", err)
			}
			clientConn.Close()
			return
		}

		// Check if the connection is from localhost
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			if p.Debug {
				log.Printf("Rejected non-localhost connection from %s", host)
			}
			clientConn.Close()
			return
		}
	}

	connID := fmt.Sprintf("%p", clientConn)
	c := &XMPPConnection{
		id:         connID,
		clientConn: clientConn,
		reader:     bufio.NewReader(clientConn),
		writer:     bufio.NewWriter(clientConn),
		debug:      p.Debug,
	}

	if c.debug {
		log.Printf("[%s] New XMPP connection from %s", connID, clientConn.RemoteAddr())
	}

	conn := c.clientConn
	cReader := bufio.NewReader(conn)

	var xh XMPPHello

	// Some clients forgets? to send the XML version.
	for {
		end, data := xmppCommandGet(cReader, c.id, conn, c.debug)
		if end {
			if c.debug {
				log.Printf("XMPP connection got cut off")
			}
			return
		}

		if strings.HasPrefix(data, "<?xml version=") {
			if c.debug {
				log.Printf("Got xml version from client")
			}
		} else {
			xml.Unmarshal([]byte(data), &xh)
			if xh.To == "" {
				if c.debug {
					log.Printf("XMPP connection got cut off as to could not be found")
				}
				conn.Close()
				return
			}
			break
		}
	}

	conn.Write([]byte("<?xml version='1.0'?><stream:stream id='133742017' xmlns:stream='http://etherx.jabber.org/streams' xml:lang='en' version='1.0' xmlns='jabber:client'><stream:features><register xmlns='http://jabber.org/features/iq-register'/><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>\n"))

	for { // until STARTTLS
		end, data := xmppCommandGet(cReader, c.id, conn, c.debug)
		if end {
			if c.debug {
				log.Printf("XMPP connection got cut off")
			}
			return
		}
		if strings.HasPrefix(data, "<starttls") {
			conn.Write([]byte("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"))
			break // Woo!
		} else {
			log.Printf("XMPP: Got unknown command, closing")
			conn.Close()
			return
		}
	}
	// Peek at the ClientHello to determine routing
	clientHello, err := peekClientHello(conn)
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
			Conn:   conn,
			buffer: bytes.NewBuffer(clientHello.raw),
		}
		tlsConn = tls.Server(replayConn, sConfig)
	} else {
		// No ClientHello was peeked, proceed normally
		tlsConn = tls.Server(conn, sConfig)
	}

	// Perform TLS handshake
	err = tlsConn.Handshake()
	if err != nil {
		log.Printf("[%s] Error on handshake: %s", c.id, err)
		return
	}
	if c.debug {
		log.Printf("[%s] Handshake finish", c.id)
	}
	tReader := bufio.NewReader(tlsConn)
	tWriter := bufio.NewWriter(tlsConn)
	c.targetServer = xh.To
	// Connect to real server
	if err := c.connectToServer(p.TLSConfig, p.DefaultRemotePort); err != nil {
		log.Printf("%s", err)
		tlsConn.Close()
		return
	}

	c.transparentProxy(tlsConn, conn, tReader, tWriter)
}

func (c *XMPPConnection) connectToServer(tlsConfig *tls.Config, port int) error {
	// Add port if not specified
	host := c.targetServer

	fallbackSN := ""
	_, addrs, err := net.LookupSRV("_xmpp-client._tcp", "tcp", host)
	if err == nil {
		fallbackSN = fmt.Sprintf("%s:%d", host, port)
		host = addrs[0].Target
		port = int(addrs[0].Port)
	}

	// Add port if not specified
	server := host
	if !strings.Contains(server, ":") {
		server = fmt.Sprintf("%s:%d", server, port)
	}

	if c.debug {
		log.Printf("[%s] Connecting to %s", c.id, server)
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

// transparentProxy switches to transparent proxy mode after authentication
func (c *XMPPConnection) transparentProxy(tlsConn *tls.Conn, conn net.Conn, clr *bufio.Reader, clw *bufio.Writer) {
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
		if c.debug {
			wew := ""
			var err error
			for {
				ibuf := make([]byte, 1)
				_, err = c.serverConn.Read(ibuf)
				if err != nil {
					break
				}
				if len(ibuf) != 0 {
					sbuf := string(ibuf)
					if sbuf == "\n" {
						log.Printf(wew)
						wew = ""
					} else {
						wew += sbuf
					}
					_, err = tlsConn.Write(ibuf)
					if err != nil {
						break
					}
				}
				err = clw.Flush()
				if err != nil {
					break
				}
			}
			errc <- err
		} else {
			_, err := io.Copy(tlsConn, c.serverConn)
			errc <- err
		}
	}()

	go func() {
		if c.debug {
			wew := ""
			stack := ""
			var err error
			for {
				ibuf := make([]byte, 1)
				_, err = tlsConn.Read(ibuf)
				if err != nil {
					break
				}
				stack += string(ibuf)
				if len(ibuf) != 0 {
					sbuf := string(ibuf)
					if sbuf == "\n" {
						log.Printf(wew)
						wew = ""
					} else {
						wew += sbuf
					}
					_, err = c.serverConn.Write(ibuf)
					if err != nil {
						break
					}
				}
				err = clw.Flush()
				if err != nil {
					break
				}
			}
			errc <- err
		} else {
			_, err := io.Copy(c.serverConn, tlsConn)
			errc <- err
		}
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

func xmppCommandGet(cReader *bufio.Reader, mcid string, conn net.Conn, debug bool) (end bool, data string) {
	line, err := cReader.ReadString('>')
	line = strings.Trim(line, " \n")
	if err != nil {
		if err != io.EOF {
			log.Printf("[%s] Error reading from client: %v", mcid, err)
		}
		return true, ""
	}

	if debug {
		log.Printf("[%s] Client: %s", mcid, strings.TrimSpace(line))
	}

	return false, line
}

// readIMAPResponse reads a complete IMAP response for a given tag
func (c *XMPPConnection) readXMPPResponse(tag string) (string, error) {
	var response strings.Builder
	for {
		line, err := c.serverReader.ReadString('>')
		line = strings.Trim(line, " \n")
		if err != nil {
			return "", err
		}

		if c.debug {
			log.Printf("[%s] Server: %s", c.id, strings.TrimSpace(line))
		}

		response.WriteString(line)

		// Check if this is the tagged response
		if strings.HasPrefix(line, tag+" ") {
			break
		}
	}

	return response.String(), nil
}
