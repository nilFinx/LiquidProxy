package liquidproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"
)

// handleSMTP handles SMTP protocol specifics
func (mp *MailProxy) handleSMTP(mc *MailConnection) {
	// Send initial SMTP greeting
	greeting := "220 localhost LiquidProxy SMTP server ready\r\n"
	mc.writer.WriteString(greeting)
	mc.writer.Flush()

	// Process commands until we get authentication
	for {
		line, err := mc.reader.ReadString('\n')
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
				mc.writer.WriteString(fmt.Sprintf("250-localhost Hello %s\r\n", domain))
				mc.writer.WriteString("250-AUTH PLAIN LOGIN\r\n")
				mc.writer.WriteString("250-8BITMIME\r\n")
				mc.writer.WriteString("250 OK\r\n")
			} else {
				mc.writer.WriteString(fmt.Sprintf("250 localhost Hello %s\r\n", domain))
			}
			mc.writer.Flush()

		case "AUTH":
			// Parse AUTH command
			authParts := strings.Fields(line)
			if len(authParts) < 2 {
				mc.writer.WriteString("501 Syntax error\r\n")
				mc.writer.Flush()
				continue
			}

			authType := strings.ToUpper(authParts[1])

			if authType == "LOGIN" {
				// Handle AUTH LOGIN
				mc.writer.WriteString("334 VXNlcm5hbWU6\r\n") // Base64 for "Username:"
				mc.writer.Flush()

				// Read username
				userLine, err := mc.reader.ReadString('\n')
				if err != nil {
					return
				}

				username, err := decodeBase64(strings.TrimSpace(userLine))
				if err != nil {
					mc.writer.WriteString("501 Invalid username encoding\r\n")
					mc.writer.Flush()
					return
				}

				// Parse username for server info
				if err := mc.parseUsername(username); err != nil {
					mc.writer.WriteString(fmt.Sprintf("535 %v\r\n", err))
					mc.writer.Flush()
					return
				}

				mc.writer.WriteString("334 UGFzc3dvcmQ6\r\n") // Base64 for "Password:"
				mc.writer.Flush()

				// Read password
				passLine, err := mc.reader.ReadString('\n')
				if err != nil {
					return
				}

				password, err := decodeBase64(strings.TrimSpace(passLine))
				if err != nil {
					mc.writer.WriteString("501 Invalid password encoding\r\n")
					mc.writer.Flush()
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
						mc.writer.WriteString("535 Failed to connect to server\r\n")
						mc.writer.Flush()
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
					mc.writer.WriteString("535 Authentication failed\r\n")
					mc.writer.Flush()
					return
				}

				if mc.debug {
					log.Printf("[%s] SMTP authentication succeeded, sending 235 to client", mc.id)
				}
				mc.writer.WriteString("235 Authentication successful\r\n")
				if err := mc.writer.Flush(); err != nil {
					if mc.debug {
						log.Printf("[%s] Error flushing 235 response: %v", mc.id, err)
					}
					return
				}
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
				mc.transparentProxy()
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
					mc.writer.WriteString("334 \r\n")
					mc.writer.Flush()

					credLine, err := mc.reader.ReadString('\n')
					if err != nil {
						return
					}
					credentials = strings.TrimSpace(credLine)
				}

				// Decode and parse credentials
				decoded, err := decodeBase64(credentials)
				if err != nil {
					mc.writer.WriteString("501 Invalid credentials encoding\r\n")
					mc.writer.Flush()
					return
				}

				// AUTH PLAIN format: \0username\0password
				parts := strings.Split(decoded, "\x00")
				if len(parts) != 3 {
					mc.writer.WriteString("501 Invalid AUTH PLAIN format\r\n")
					mc.writer.Flush()
					return
				}

				username := parts[1]
				password := parts[2]

				// Parse username for server info
				if err := mc.parseUsername(username); err != nil {
					mc.writer.WriteString(fmt.Sprintf("535 %v\r\n", err))
					mc.writer.Flush()
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
						mc.writer.WriteString("535 Failed to connect to server\r\n")
						mc.writer.Flush()
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
					mc.writer.WriteString("535 Authentication failed\r\n")
					mc.writer.Flush()
					return
				}

				if mc.debug {
					log.Printf("[%s] SMTP authentication succeeded, sending 235 to client", mc.id)
				}
				mc.writer.WriteString("235 Authentication successful\r\n")
				if err := mc.writer.Flush(); err != nil {
					if mc.debug {
						log.Printf("[%s] Error flushing 235 response: %v", mc.id, err)
					}
					return
				}
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
				mc.transparentProxy()
				if mc.debug {
					log.Printf("[%s] Returned from transparentProxy()", mc.id)
				}
				return

			} else {
				mc.writer.WriteString("504 Unrecognized authentication type\r\n")
				mc.writer.Flush()
			}

		case "QUIT":
			mc.writer.WriteString("221 Bye\r\n")
			mc.writer.Flush()
			return

		case "NOOP":
			mc.writer.WriteString("250 OK\r\n")
			mc.writer.Flush()

		case "RSET":
			mc.writer.WriteString("250 OK\r\n")
			mc.writer.Flush()

		default:
			// Before authentication, reject other commands
			mc.writer.WriteString("530 Please authenticate first\r\n")
			mc.writer.Flush()
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
func (mc *MailConnection) transparentSMTPProxy() {
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
			mc.writer.WriteString(line + "\r\n")
			if err := mc.writer.Flush(); err != nil {
				if mc.debug {
					log.Printf("[%s] Error flushing server response to client: %v", mc.id, err)
				}
				break
			}
		}
		if err := scanner.Err(); err != nil && mc.debug {
			log.Printf("[%s] Server scanner error: %v", mc.id, err)
		}
		if mc.debug {
			log.Printf("[%s] Server-to-client relay goroutine exiting", mc.id)
		}
		mc.Close()
	}()

	// Client to server - rewrite MAIL FROM commands
	if mc.debug {
		log.Printf("[%s] Starting client-to-server relay loop", mc.id)
		log.Printf("[%s] clientConn type: %T", mc.id, mc.clientConn)
		log.Printf("[%s] serverConn type: %T", mc.id, mc.serverConn)
	}

	scanner := bufio.NewScanner(mc.clientConn)
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

	mc.Close()
}
