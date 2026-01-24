package liquidproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

func imapCommandGet(cReader *bufio.Reader, mcid string, conn net.Conn, debug bool) (end bool, t string, cmd string, part []string) {
	for {
		line, err := cReader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[%s] Error reading from client: %v", mcid, err)
			}
			return true, "", "", []string{}
		}

		if debug {
			log.Printf("[%s] Client: %s", mcid, strings.TrimSpace(line))
		}

		// Parse IMAP command
		parts := strings.Fields(line)
		if len(parts) < 2 {
			conn.Write([]byte("* BAD Invalid command\r\n"))
			continue
		}

		tag := parts[0]
		command := strings.ToUpper(parts[1])
		return false, tag, command, parts
	}
}

// handleIMAP handles IMAP protocol specifics
func (mp *MailProxy) handleIMAP(mc *MailConnection, STARTTLS bool) {
	HELLO := []byte("* OK i will be launching a court case against apple for waiting for data even with MAIL over TLS/SSL port\r\n")
	conn := mc.clientConn
	if STARTTLS {
		cReader := bufio.NewReader(conn)
		// Send initial IMAP greeting
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		conn.Write(HELLO)

		for { // until STARTTLS
			end, tag, command, _ := imapCommandGet(cReader, mc.id, conn, mc.debug)
			if end {
				return
			}

			if command == "STARTTLS" {
				conn.Write([]byte(fmt.Sprintf("%s OK Begin TLS negotiation now\r\n", tag)))
				break // Woo!
			} else if command == "CAPABILITY" {
				// Respond with basic capabilities
				// AUTH=PLAIN AUTH=LOGIN
				conn.Write([]byte("* CAPABILITY IMAP4rev1 STARTTLS\r\n"))
				conn.Write([]byte(fmt.Sprintf("%s OK CAPABILITY completed\r\n", tag)))

			} else if command == "NOOP" {
				conn.Write([]byte(fmt.Sprintf("%s OK NOOP Fuck Apple\r\n", tag)))

			} else if command == "LOGOUT" {
				conn.Write([]byte("* BYE LiquidProxy logging out\r\n"))
				conn.Write([]byte(fmt.Sprintf("%s OK LOGOUT completed\r\n", tag)))
				return

			} else {
				// Before authentication, reject other commands
				conn.Write([]byte(fmt.Sprintf("%s NO Please authenticate first\r\n", tag)))
			}
		}
	}
	// Peek at the ClientHello to determine routing
	clientHello, err := peekClientHello(conn)
	if err != nil {
		log.Printf("[%s] Error on peeking handshake: %s", mc.id, err)
		return
	}

	if clientHello.isModernClient && *blockModernConnections {
		return
	}

	var sConfig *tls.Config
	// Create TLS server config
	if mp.ServerTLSConfig == nil {
		sConfig = new(tls.Config)
	} else {
		sConfig = mp.ServerTLSConfig
	}
	//sConfig.Certificates = []tls.Certificate{sConfig.RootCAs}
	sConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &mp.ServerCA, nil
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
		log.Printf("[%s] Error on handshake: %s", mc.id, err)
		return
	}
	if mc.debug {
		log.Printf("[%s] Handshake finish", mc.id)
	}
	tReader := bufio.NewReader(tlsConn)
	tWriter := bufio.NewWriter(tlsConn)
	tlsConn.Write(HELLO)
	for { // until LOGIN
		end, tag, command, parts := imapCommandGet(tReader, mc.id, tlsConn, mc.debug)
		if end {
			if mc.debug {
				log.Printf("[%s] The end...", mc.id)
			}
			return
		}

		// Check for authentication commands
		if command == "LOGIN" && len(parts) >= 4 {
			// Extract username and password
			username := strings.Trim(parts[2], "\"")
			password := strings.Trim(parts[3], "\"")

			// Parse username for server info
			if err := mc.parseUsername(username); err != nil {
				tlsConn.Write([]byte(fmt.Sprintf("%s NO %v\r\n", tag, err)))
				return
			}

			// Connect to real server
			if err := mc.connectToServer(mp.TLSConfig, mp.DefaultRemotePort); err != nil {
				tlsConn.Write([]byte(fmt.Sprintf("%s NO Failed to connect to server: %v\r\n", tag, err)))
				return
			}

			// Read server greeting
			serverGreeting, err := mc.serverReader.ReadString('\n')
			if err != nil {
				tlsConn.Write([]byte(fmt.Sprintf("%s NO Failed to read server greeting\r\n", tag)))
				return
			}

			if mc.debug {
				log.Printf("[%s] Server: %s", mc.id, strings.TrimSpace(serverGreeting))
			}

			// Send real login command
			realLogin := fmt.Sprintf("%s LOGIN \"%s\" \"%s\"\r\n", tag, mc.realUsername, password)
			mc.serverWriter.WriteString(realLogin)
			mc.serverWriter.Flush()

			// Read response
			response, err := mc.readIMAPResponse(tag)
			if err != nil {
				tlsConn.Write([]byte(fmt.Sprintf("%s NO Authentication failed\r\n", tag)))
				return
			}

			// Forward response to client
			tlsConn.Write([]byte(response))

			// Check if authentication succeeded
			if strings.Contains(response, tag+" OK") {
				mc.authenticated = true
				if mp.Debug {
					log.Printf("[%s] Successfully authenticated to %s", mc.id, mc.targetServer)
				}

				// Switch to transparent proxy mode
				mc.transparentProxy(tlsConn, conn, tReader, tWriter)
				return
			}

			// Authentication failed
			return

		} else if command == "AUTHENTICATE" && len(parts) >= 3 {
			authType := strings.ToUpper(parts[2])
			if authType == "PLAIN" {
				// Send continuation response
				tlsConn.Write([]byte("+ \r\n"))

				// Read base64 encoded credentials
				credLine, err := mc.reader.ReadString('\n')
				if err != nil {
					tlsConn.Write([]byte(fmt.Sprintf("%s NO Authentication failed\r\n", tag)))
					return
				}

				// Decode credentials
				decoded, err := decodeBase64(strings.TrimSpace(credLine))
				if err != nil {
					tlsConn.Write([]byte(fmt.Sprintf("%s NO Invalid credentials encoding\r\n", tag)))
					return
				}

				// AUTH PLAIN format: \0username\0password
				parts := strings.Split(decoded, "\x00")
				if len(parts) != 3 {
					tlsConn.Write([]byte(fmt.Sprintf("%s NO Invalid AUTH PLAIN format\r\n", tag)))
					return
				}

				username := parts[1]
				password := parts[2]

				// Parse username for server info
				if err := mc.parseUsername(username); err != nil {
					tlsConn.Write([]byte(fmt.Sprintf("%s NO %v\r\n", tag, err)))
					return
				}

				// Connect to real server
				if err := mc.connectToServer(mp.TLSConfig, mp.DefaultRemotePort); err != nil {
					tlsConn.Write([]byte(fmt.Sprintf("%s NO Failed to connect to server: %v\r\n", tag, err)))
					return
				}

				// Read server greeting
				serverGreeting, err := mc.serverReader.ReadString('\n')
				if err != nil {
					tlsConn.Write([]byte(fmt.Sprintf("%s NO Failed to read server greeting\r\n", tag)))
					return
				}

				if mc.debug {
					log.Printf("[%s] Server: %s", mc.id, strings.TrimSpace(serverGreeting))
				}

				// Send AUTHENTICATE PLAIN to server
				mc.serverWriter.WriteString(fmt.Sprintf("%s AUTHENTICATE PLAIN\r\n", tag))
				mc.serverWriter.Flush()

				// Read continuation response
				contResp, err := mc.serverReader.ReadString('\n')
				if err != nil || !strings.HasPrefix(contResp, "+") {
					tlsConn.Write([]byte(fmt.Sprintf("%s NO Server rejected authentication\r\n", tag)))
					return
				}

				// Send real credentials
				realCreds := encodeBase64(fmt.Sprintf("\x00%s\x00%s", mc.realUsername, password))
				mc.serverWriter.WriteString(realCreds + "\r\n")
				mc.serverWriter.Flush()

				// Read response
				response, err := mc.readIMAPResponse(tag)
				if err != nil {
					tlsConn.Write([]byte(fmt.Sprintf("%s NO Authentication failed\r\n", tag)))
					return
				}

				// Forward response to client
				tlsConn.Write([]byte(response))

				// Check if authentication succeeded
				if strings.Contains(response, tag+" OK") {
					mc.authenticated = true
					if mp.Debug {
						log.Printf("[%s] Successfully authenticated to %s", mc.id, mc.targetServer)
					}

					// Switch to transparent proxy mode
					mc.transparentProxy(tlsConn, conn, tReader, tWriter)
					return
				}

				// Authentication failed
				return
			} else {
				tlsConn.Write([]byte(fmt.Sprintf("%s NO Unsupported authentication mechanism\r\n", tag)))
			}
		} else if command == "CAPABILITY" {
			// Respond with basic capabilities
			// AUTH=PLAIN AUTH=LOGIN
			tlsConn.Write([]byte("* CAPABILITY IMAP4rev1 STARTTLS\r\n"))
			tlsConn.Write([]byte(fmt.Sprintf("%s OK CAPABILITY completed\r\n", tag)))
		} else if command == "NOOP" {
			tlsConn.Write([]byte(fmt.Sprintf("%s OK NOOP Fuck Apple\r\n", tag)))
		} else if command == "LOGOUT" {
			tlsConn.Write([]byte("* BYE LiquidProxy logging out\r\n"))
			tlsConn.Write([]byte(fmt.Sprintf("%s OK LOGOUT completed\r\n", tag)))
			return
		} else {
			// Before authentication, reject other commands
			tlsConn.Write([]byte(fmt.Sprintf("%s NO Please authenticate first\r\n", tag)))
		}
	}
}

// readIMAPResponse reads a complete IMAP response for a given tag
func (mc *MailConnection) readIMAPResponse(tag string) (string, error) {
	var response strings.Builder

	for {
		line, err := mc.serverReader.ReadString('\n')
		if err != nil {
			return "", err
		}

		if mc.debug {
			log.Printf("[%s] Server: %s", mc.id, strings.TrimSpace(line))
		}

		response.WriteString(line)

		// Check if this is the tagged response
		if strings.HasPrefix(line, tag+" ") {
			break
		}
	}

	return response.String(), nil
}
