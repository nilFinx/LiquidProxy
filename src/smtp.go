package liquidproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"
)

var (
	smtpPort    = flag.Int("smtp-port", 6533, "SMTP proxy port")
	disableSMTP = flag.Bool("no-smtp", false, "Disable SMTP proxy")
)

// handleSMTP handles SMTP protocol specifics
func (mp *MailProxy) handleSMTP(mc *MailConnection) {
	// Peek at the ClientHello to determine routing
	clientHello, err := peekClientHello(mc.clientConn)
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
			Conn:   mc.clientConn,
			buffer: bytes.NewBuffer(clientHello.raw),
		}
		tlsConn = tls.Server(replayConn, sConfig)
	} else {
		// No ClientHello was peeked, proceed normally
		tlsConn = tls.Server(mc.clientConn, sConfig)
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
	// Send initial SMTP greeting
	greeting := "220 localhost LiquidProxy SMTP server ready\r\n"
	tlsConn.Write([]byte(greeting))

	// Process commands until we get authentication
	for {
		line, err := tReader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[%s] Error reading from client: %v", mc.id, err)
			}
			return
		}

		if mc.debug {
			log.Printf("[%s] Client: %s", mc.id, strings.TrimSpace(line))
		}

		// Parse SMTP command
		command := strings.ToUpper(strings.Fields(line)[0])

		switch command {
		case "EHLO", "HELO":
			// Respond with capabilities
			domain := "localhost"
			if len(strings.Fields(line)) > 1 {
				domain = strings.Fields(line)[1]
			}

			if command == "EHLO" {
				tlsConn.Write([]byte(fmt.Sprintf("250-localhost Hello %s\r\n", domain)))
				tlsConn.Write([]byte("250-AUTH PLAIN LOGIN\r\n"))
				tlsConn.Write([]byte("250-8BITMIME\r\n"))
				tlsConn.Write([]byte("250 OK\r\n"))
			} else {
				tlsConn.Write([]byte(fmt.Sprintf("250 localhost Hello %s\r\n", domain)))
			}

		case "AUTH":
			// Parse AUTH command
			authParts := strings.Fields(line)
			if len(authParts) < 2 {
				tlsConn.Write([]byte("501 Syntax error\r\n"))

				continue
			}

			authType := strings.ToUpper(authParts[1])

			if authType == "LOGIN" {
				// Handle AUTH LOGIN
				tlsConn.Write([]byte("334 VXNlcm5hbWU6\r\n")) // Base64 for "Username:"

				// Read username
				userLine, err := tReader.ReadString('\n')
				if err != nil {
					return
				}

				username, err := decodeBase64(strings.TrimSpace(userLine))
				if err != nil {
					tlsConn.Write([]byte("501 Invalid username encoding\r\n"))

					return
				}

				// Parse username for server info
				if err := mc.parseUsername(username); err != nil {
					tlsConn.Write([]byte(fmt.Sprintf("535 %v\r\n", err)))

					return
				}

				tlsConn.Write([]byte("334 UGFzc3dvcmQ6\r\n")) // Base64 for "Password:"

				// Read password
				passLine, err := tReader.ReadString('\n')
				if err != nil {
					return
				}

				password, err := decodeBase64(strings.TrimSpace(passLine))
				if err != nil {
					tlsConn.Write([]byte("501 Invalid password encoding\r\n"))

					return
				}

				// Connect and authenticate
				if mc.debug {
					log.Printf("[%s] Attempting to connect to server on port 587", mc.id)
				}
				if err := mc.connectToServer(mp.TLSConfig, 587); err != nil {
					if mc.debug {
						log.Printf("[%s] Failed to connect on port 587: %v, trying port 465", mc.id, err)
					}
					// Try port 465 if 587 fails
					if err := mc.connectToServer(mp.TLSConfig, 465); err != nil {
						if mc.debug {
							log.Printf("[%s] Failed to connect on port 465: %v", mc.id, err)
						}
						tlsConn.Write([]byte("535 Failed to connect to server\r\n"))

						return
					}
				}

				// Perform SMTP authentication with real server
				if mc.debug {
					log.Printf("[%s] Starting SMTP authentication with %s", mc.id, mc.targetServer)
				}
				if err := mc.authenticateSMTP(authType, mc.realUsername, password, mp.TLSConfig); err != nil {
					if mc.debug {
						log.Printf("[%s] SMTP authentication failed: %v", mc.id, err)
					}
					tlsConn.Write([]byte("535 Authentication failed\r\n"))

					return
				}

				if mc.debug {
					log.Printf("[%s] SMTP authentication succeeded, sending 235 to client", mc.id)
				}
				tlsConn.Write([]byte("235 Authentication successful\r\n"))
				if mc.debug {
					log.Printf("[%s] Successfully sent 235 response to client", mc.id)
				}

				mc.authenticated = true
				if mp.Debug {
					log.Printf("[%s] Successfully authenticated to %s", mc.id, mc.targetServer)
				}

				// Switch to transparent proxy mode
				if mc.debug {
					log.Printf("[%s] About to switch to transparent proxy mode", mc.id)
				}
				mc.transparentSMTPProxy(tlsConn)
				if mc.debug {
					log.Printf("[%s] Returned from transparentProxy()", mc.id)
				}
				return

			} else if authType == "PLAIN" {
				// Handle AUTH PLAIN
				var credentials string
				if len(authParts) > 2 {
					// Credentials provided inline
					credentials = authParts[2]
				} else {
					// Request credentials
					tlsConn.Write([]byte("334 \r\n"))

					credLine, err := tReader.ReadString('\n')
					if err != nil {
						return
					}
					credentials = strings.TrimSpace(credLine)
				}

				// Decode and parse credentials
				decoded, err := decodeBase64(credentials)
				if err != nil {
					tlsConn.Write([]byte("501 Invalid credentials encoding\r\n"))

					return
				}

				// AUTH PLAIN format: \0username\0password
				parts := strings.Split(decoded, "\x00")
				if len(parts) != 3 {
					tlsConn.Write([]byte("501 Invalid AUTH PLAIN format\r\n"))

					return
				}

				username := parts[1]
				password := parts[2]

				// Parse username for server info
				if err := mc.parseUsername(username); err != nil {
					tlsConn.Write([]byte(fmt.Sprintf("535 %v\r\n", err)))

					return
				}

				// Connect and authenticate
				if mc.debug {
					log.Printf("[%s] Attempting to connect to server on port 587", mc.id)
				}
				if err := mc.connectToServer(mp.TLSConfig, 587); err != nil {
					if mc.debug {
						log.Printf("[%s] Failed to connect on port 587: %v, trying port 465", mc.id, err)
					}
					// Try port 465 if 587 fails
					if err := mc.connectToServer(mp.TLSConfig, 465); err != nil {
						if mc.debug {
							log.Printf("[%s] Failed to connect on port 465: %v", mc.id, err)
						}
						tlsConn.Write([]byte("535 Failed to connect to server\r\n"))

						return
					}
				}

				// Perform SMTP authentication with real server
				if mc.debug {
					log.Printf("[%s] Starting SMTP authentication with %s", mc.id, mc.targetServer)
				}
				if err := mc.authenticateSMTP(authType, mc.realUsername, password, mp.TLSConfig); err != nil {
					if mc.debug {
						log.Printf("[%s] SMTP authentication failed: %v", mc.id, err)
					}
					tlsConn.Write([]byte("535 Authentication failed\r\n"))

					return
				}

				if mc.debug {
					log.Printf("[%s] SMTP authentication succeeded, sending 235 to client", mc.id)
				}
				tlsConn.Write([]byte("235 Authentication successful\r\n"))
				/*if err :=; err != nil {
					if mc.debug {
						log.Printf("[%s] Error flushing 235 response: %v", mc.id, err)
					}
					return
				}*/
				if mc.debug {
					log.Printf("[%s] Successfully sent 235 response to client", mc.id)
				}

				mc.authenticated = true
				if mp.Debug {
					log.Printf("[%s] Successfully authenticated to %s", mc.id, mc.targetServer)
				}

				// Switch to transparent proxy mode
				if mc.debug {
					log.Printf("[%s] About to switch to transparent proxy mode", mc.id)
				}
				mc.transparentSMTPProxy(tlsConn)
				if mc.debug {
					log.Printf("[%s] Returned from transparentProxy()", mc.id)
				}
				return

			} else {
				tlsConn.Write([]byte("504 Unrecognized authentication type\r\n"))

			}

		case "QUIT":
			tlsConn.Write([]byte("221 Bye\r\n"))

			return

		case "NOOP":
			tlsConn.Write([]byte("250 OK\r\n"))

		case "RSET":
			tlsConn.Write([]byte("250 OK\r\n"))

		default:
			// Before authentication, reject other commands
			tlsConn.Write([]byte("530 Please authenticate first\r\n"))

		}
	}
}

// authenticateSMTP performs SMTP authentication with the real server
func (mc *MailConnection) authenticateSMTP(authType, username, password string, tlsConfig *tls.Config) error {
	// Read server greeting
	greeting, err := mc.serverReader.ReadString('\n')
	if err != nil {
		return err
	}

	if mc.debug {
		log.Printf("[%s] Server: %s", mc.id, strings.TrimSpace(greeting))
	}

	// Send EHLO
	mc.serverWriter.WriteString("EHLO localhost\r\n")
	mc.serverWriter.Flush()

	// Read EHLO response and check for STARTTLS
	hasSTARTTLS := false
	for {
		line, err := mc.serverReader.ReadString('\n')
		if err != nil {
			return err
		}

		if mc.debug {
			log.Printf("[%s] Server: %s", mc.id, strings.TrimSpace(line))
		}

		// Check for STARTTLS support
		if !mc.tlsEnabled && strings.Contains(line, "STARTTLS") {
			hasSTARTTLS = true
		}

		// Check if this is the last line
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	// If STARTTLS is supported and we're not already using TLS, upgrade the connection
	if hasSTARTTLS && !mc.tlsEnabled {
		// Send STARTTLS command
		mc.serverWriter.WriteString("STARTTLS\r\n")
		mc.serverWriter.Flush()

		response, err := mc.serverReader.ReadString('\n')
		if err != nil {
			return err
		}

		if mc.debug {
			log.Printf("[%s] STARTTLS response: %s", mc.id, strings.TrimSpace(response))
		}

		if !strings.HasPrefix(response, "220") {
			return fmt.Errorf("STARTTLS failed: %s", response)
		}

		// Upgrade connection
		var tlsConf *tls.Config
		// CRITICAL: Copy the TLS config to get RootCAs for Snow Leopard
		if tlsConfig != nil {
			tlsConf = tlsConfig
			tlsConf.ServerName = mc.targetServer
		} else {
			tlsConf = &tls.Config{
				ServerName: mc.targetServer,
			}
			if mc.debug {
				log.Printf("[%s] WARNING: No TLS config provided for STARTTLS!", mc.id)
			}
		}

		if mc.debug {
			log.Printf("[%s] Starting TLS handshake with %s", mc.id, mc.targetServer)
		}

		tlsConn := tls.Client(mc.serverConn, tlsConf)
		if err := tlsConn.Handshake(); err != nil {
			if mc.debug {
				log.Printf("[%s] TLS handshake failed: %v", mc.id, err)
			}
			return fmt.Errorf("TLS handshake failed: %w", err)
		}

		mc.serverConn = tlsConn
		mc.serverReader = bufio.NewReader(mc.serverConn)
		mc.serverWriter = bufio.NewWriter(mc.serverConn)
		mc.tlsEnabled = true

		if mc.debug {
			log.Printf("[%s] TLS connection established successfully", mc.id)
		}

		// Send EHLO again after STARTTLS
		if mc.debug {
			log.Printf("[%s] Sending EHLO after STARTTLS", mc.id)
		}
		mc.serverWriter.WriteString("EHLO localhost\r\n")
		if err := mc.serverWriter.Flush(); err != nil {
			if mc.debug {
				log.Printf("[%s] Error flushing EHLO after STARTTLS: %v", mc.id, err)
			}
			return fmt.Errorf("failed to send EHLO after STARTTLS: %w", err)
		}

		// Read EHLO response again
		if mc.debug {
			log.Printf("[%s] Reading EHLO response after STARTTLS", mc.id)
		}
		for {
			line, err := mc.serverReader.ReadString('\n')
			if err != nil {
				if mc.debug {
					log.Printf("[%s] Error reading EHLO response after STARTTLS: %v", mc.id, err)
				}
				return err
			}

			if mc.debug {
				log.Printf("[%s] Server: %s", mc.id, strings.TrimSpace(line))
			}

			if len(line) >= 4 && line[3] == ' ' {
				break
			}
		}
	}

	// Perform authentication
	if authType == "LOGIN" {
		if mc.debug {
			log.Printf("[%s] Sending AUTH LOGIN", mc.id)
		}
		mc.serverWriter.WriteString("AUTH LOGIN\r\n")
		mc.serverWriter.Flush()

		// Read username prompt
		response, err := mc.serverReader.ReadString('\n')
		if err != nil {
			if mc.debug {
				log.Printf("[%s] Error reading AUTH LOGIN response: %v", mc.id, err)
			}
			return err
		}

		if mc.debug {
			log.Printf("[%s] AUTH LOGIN response: %s", mc.id, strings.TrimSpace(response))
		}

		if !strings.HasPrefix(response, "334") {
			return fmt.Errorf("AUTH LOGIN failed: %s", response)
		}

		// Send username
		if mc.debug {
			log.Printf("[%s] Sending username", mc.id)
		}
		mc.serverWriter.WriteString(encodeBase64(username) + "\r\n")
		mc.serverWriter.Flush()

		// Read password prompt
		response, err = mc.serverReader.ReadString('\n')
		if err != nil {
			if mc.debug {
				log.Printf("[%s] Error reading password prompt: %v", mc.id, err)
			}
			return err
		}

		if mc.debug {
			log.Printf("[%s] Password prompt response: %s", mc.id, strings.TrimSpace(response))
		}

		if !strings.HasPrefix(response, "334") {
			return fmt.Errorf("AUTH LOGIN failed: %s", response)
		}

		// Send password
		if mc.debug {
			log.Printf("[%s] Sending password", mc.id)
		}
		mc.serverWriter.WriteString(encodeBase64(password) + "\r\n")
		mc.serverWriter.Flush()

	} else if authType == "PLAIN" {
		// Encode credentials
		credentials := encodeBase64(fmt.Sprintf("\x00%s\x00%s", username, password))
		if mc.debug {
			log.Printf("[%s] Sending AUTH PLAIN", mc.id)
		}
		mc.serverWriter.WriteString(fmt.Sprintf("AUTH PLAIN %s\r\n", credentials))
		mc.serverWriter.Flush()
	}

	// Read authentication response
	response, err := mc.serverReader.ReadString('\n')
	if err != nil {
		if mc.debug {
			log.Printf("[%s] Error reading authentication response: %v", mc.id, err)
		}
		return err
	}

	if mc.debug {
		log.Printf("[%s] Authentication response: %s", mc.id, strings.TrimSpace(response))
	}

	if !strings.HasPrefix(response, "235") {
		return fmt.Errorf("authentication failed: %s", response)
	}

	return nil
}

// transparentSMTPProxy handles SMTP-specific transparent proxying with MAIL FROM rewriting
func (mc *MailConnection) transparentSMTPProxy(tlsConn *tls.Conn) {
	if mc.debug {
		log.Printf("[%s] Entered transparentSMTPProxy", mc.id)
	}

	// Server to client - log responses if debug enabled
	go func() {
		if mc.debug {
			log.Printf("[%s] Starting server-to-client relay goroutine", mc.id)
		}
		scanner := bufio.NewScanner(mc.serverConn)
		for scanner.Scan() {
			line := scanner.Text()
			if mc.debug {
				log.Printf("[%s] Server response: %s", mc.id, line)
			}
			tlsConn.Write([]byte(line + "\r\n"))
			/*if err :=; err != nil {
				if mc.debug {
					log.Printf("[%s] Error flushing server response to client: %v", mc.id, err)
				}
				break
			}*/
		}
		if err := scanner.Err(); err != nil && mc.debug {
			log.Printf("[%s] Server scanner error: %v", mc.id, err)
		}
		if mc.debug {
			log.Printf("[%s] Server-to-client relay goroutine exiting", mc.id)
		}
		tlsConn.Close()
	}()

	// Client to server - rewrite MAIL FROM commands
	if mc.debug {
		log.Printf("[%s] Starting client-to-server relay loop", mc.id)
		log.Printf("[%s] clientConn type: %T", mc.id, tlsConn)
		log.Printf("[%s] serverConn type: %T", mc.id, mc.serverConn)
	}

	scanner := bufio.NewScanner(tlsConn)
	for scanner.Scan() {
		line := scanner.Text()

		if mc.debug {
			log.Printf("[%s] Client command: %s", mc.id, line)
		}

		// Check if this is a MAIL FROM command
		upperLine := strings.ToUpper(line)
		if strings.HasPrefix(upperLine, "MAIL FROM:") {
			// Extract the email address
			fromMatch := regexp.MustCompile(`<([^>]+)>`).FindStringSubmatch(line)
			if len(fromMatch) > 1 {
				email := fromMatch[1]
				// Check if it contains our proxy suffix
				if strings.Contains(email, "@imap.mail.me.com") || strings.Contains(email, "@smtp.mail.me.com") {
					// Extract the real email (everything before the last @)
					lastAt := strings.LastIndex(email, "@")
					if lastAt > 0 {
						realEmail := email[:lastAt]
						// Rewrite the command
						line = strings.Replace(line, email, realEmail, 1)
						if mc.debug {
							log.Printf("[%s] Rewritten MAIL FROM: %s", mc.id, line)
						}
					}
				}
			}
		}

		// Also check for From: header in email data
		if strings.HasPrefix(line, "From:") {
			// Look for email addresses with our proxy suffix
			fromMatch := regexp.MustCompile(`<([^>]+@(?:imap|smtp)\.mail\.[^>]+)>`).FindAllStringSubmatch(line, -1)
			for _, match := range fromMatch {
				if len(match) > 1 {
					email := match[1]
					// Extract the real email (everything before the last @)
					lastAt := strings.LastIndex(email, "@")
					if lastAt > 0 {
						realEmail := email[:lastAt]
						// Rewrite the From header
						line = strings.Replace(line, email, realEmail, 1)
						if mc.debug {
							log.Printf("[%s] Rewritten From header: %s", mc.id, line)
						}
					}
				}
			}
		}

		// Send the (possibly rewritten) command to server
		mc.serverWriter.WriteString(line + "\r\n")
		if err := mc.serverWriter.Flush(); err != nil {
			if mc.debug {
				log.Printf("[%s] Error flushing client command to server: %v", mc.id, err)
			}
			break
		}

		// Check for QUIT command
		if strings.ToUpper(strings.TrimSpace(line)) == "QUIT" {
			if mc.debug {
				log.Printf("[%s] Received QUIT command, exiting relay loop", mc.id)
			}
			// Read final response and close
			mc.serverReader.ReadString('\n')
			break
		}
	}

	if err := scanner.Err(); err != nil && mc.debug {
		log.Printf("[%s] Client scanner error: %v", mc.id, err)
	}
	if mc.debug {
		log.Printf("[%s] Client-to-server relay loop exited", mc.id)
	}

	tlsConn.Close()
}
