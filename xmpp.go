package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

var (
	xmppPort   = flag.Int("xmpp-port", 6536, "XMPP proxy port")
	enableXMPP = flag.Bool("enable-xmpp", false, "Enable XMPP proxy")
)

type XMPPProxy struct {
	Port int

	// Default remote port if not specified
	DefaultRemotePort     int
	DefaultRemoteSTLSPort int

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
	id                    string
	clientConn            net.Conn
	serverConn            net.Conn
	protocol              string
	targetServer          string
	realUsername          string
	authenticated         bool
	tlsEnabled            bool
	reader                *bufio.Reader
	writer                *bufio.Writer
	serverReader          *bufio.Reader
	serverWriter          *bufio.Writer
	debug                 bool
	defaultRemoteSTLSPort int
}

func xmppMain(systemRoots *x509.CertPool, ca tls.Certificate, tlsServerConfig *tls.Config) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    systemRoots,
	}

	if *enableXMPP {
		proxy := &XMPPProxy{
			Port:                  *xmppPort,
			DefaultRemotePort:     5223,
			DefaultRemoteSTLSPort: 5222,
			TLSConfig:             tlsConfig,
			ServerTLSConfig:       tlsServerConfig,
			Debug:                 *debug,
			ServerCA:              ca,
		}
		proxy.Start()

		log.Printf("XMPP Proxy started (%d)", *xmppPort)
	}
}

// Start starts the mail proxy listener
func (p *XMPPProxy) Start() {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.Port))
	if err != nil {
		log.Fatalf("Failed to start XMPP proxy on port %d: %s", p.Port, err)
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
		id:                    connID,
		clientConn:            clientConn,
		reader:                bufio.NewReader(clientConn),
		writer:                bufio.NewWriter(clientConn),
		debug:                 p.Debug,
		defaultRemoteSTLSPort: p.DefaultRemoteSTLSPort,
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
			if c.debug {
				log.Printf("XMPP: Got unknown command, closing")
			}
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
	c.targetServer = xh.To
	err, stls := c.connectToServer(p.TLSConfig, p.DefaultRemotePort, false)
	if stls {
		if c.debug {
			log.Printf("[%s] Failed DTLS, attempting STLS", c.id)
		}
		err, _ = c.connectToServer(p.TLSConfig, p.DefaultRemoteSTLSPort, true)
		if err == nil {
			if c.debug {
				log.Printf("[%s] Connected", c.id)
			}
			scr := bufio.NewReader(c.serverConn)
			_, err = c.serverConn.Write([]byte("<?xml version=\"1.0\"?>"))
			_, err = c.serverConn.Write([]byte("<stream:stream xmlns:stream=\"http://etherx.jabber.org/streams\" xml:lang=\"en\" xmlns:xml=\"http://www.w3.org/XML/1998/namespace\" to=\"" + xh.To + "\" xmlns=\"jabber:client\" version=\"1.0\">"))
			//_, err = c.serverConn.Write([]byte("<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>\r\n"))

			for { // until STARTTLS
				end, data := xmppCommandGet(scr, c.id, c.serverConn, c.debug)
				if end {
					if c.debug {
						log.Printf("XMPP connection got cut off")
					}
					return
				}
				if strings.HasPrefix(data, "<?xml") { // Nobody cares
				} else if strings.HasPrefix(data, "<stream:stream") {
				} else if strings.HasPrefix(data, "<required") {
				} else if strings.HasPrefix(data, "</starttls") {
				} else if strings.HasPrefix(data, "</stream:features") {
				} else if strings.HasPrefix(data, "<proceed") {
					break
				} else if strings.HasPrefix(data, "<starttls") {
				} else if strings.HasPrefix(data, "<stream:features") {
					c.serverConn.Write([]byte("<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>\r\n"))
				} else {
					log.Printf("%s", data)
					if c.debug {
						log.Printf("XMPP server: Got unknown command, closing")
					}
					c.serverConn.Close()
					return
				}
			}

			if c.debug {
				log.Printf("[%s] Handshake...", c.id)
			}

			var tlsConf *tls.Config
			if p.TLSConfig == nil {
				tlsConf = &tls.Config{
					ServerName: c.targetServer,
				}
			} else {
				tlsConf = p.TLSConfig
				tlsConf.ServerName = c.targetServer
			}

			stlsConn := tls.Client(c.serverConn, tlsConf)
			if err := tlsConn.Handshake(); err != nil {
				conn.Close()
				log.Printf("[%s] Server TLS handshake failed: %s", c.id, err)
			}
			c.serverConn = stlsConn
			if c.debug {
				log.Printf("[%s] Handshake should be done now", c.id)
			}
		}
	}
	if err != nil {
		log.Printf("%s", err)
		tlsConn.Close()
		return
	}

	transparentProxy(c.id, c.debug, tlsConn, c.serverConn)
}

func (c *XMPPConnection) connectToServer(tlsConfig *tls.Config, port int, stls bool) (er error, requestsstls bool) {
	var sn string
	if stls {
		sn = "xmpp-client"
	} else {
		sn = "xmpps-client"
	}
	host := c.targetServer
	fallbackSN := ""
	_, addrs, err := net.LookupSRV(sn, "tcp", host)
	if !stls && (addrs[0].Target == "." || addrs[0].Port == 5222 || addrs[0].Port == uint16(c.defaultRemoteSTLSPort)) {
		return fmt.Errorf("DTLS specified with no server STLS support"), !stls
	} else {
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

	var tlsConf *tls.Config
	if !stls {
		if tlsConfig == nil {
			tlsConf = &tls.Config{
				ServerName: host,
			}
		} else {
			tlsConf = tlsConfig
			tlsConf.ServerName = host
		}
	}

	var conn net.Conn

	if !stls {
		conn, err = tls.Dial("tcp", server, tlsConf)
	} else {
		conn, err = net.Dial("tcp", server)
	}

	if err != nil {
		if fallbackSN != "" {
			var err2 error
			if !stls {
				conn, err2 = tls.Dial("tcp", fallbackSN, tlsConf)
			} else {
				conn, err2 = net.Dial("tcp", fallbackSN)
			}
			if err2 != nil {
				return fmt.Errorf("%s, %s", err, err2), !stls
			}
			c.serverConn = conn
			return nil, stls
		}
		return err, !stls
	}

	c.serverConn = conn

	return nil, stls
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
