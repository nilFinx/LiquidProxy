package liquidproxy

import (
	"fmt"
	"io"
	"log"
	"strings"
)

// handleIMAP handles IMAP protocol specifics
func (mp *MailProxy) handleIMAP(mc *MailConnection) {
	// Send initial IMAP greeting
	greeting := "* OK LiquidProxy IMAP server ready\r\n"
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

		// Parse IMAP command
		parts := strings.Fields(line)
		if len(parts) < 2 {
			mc.writer.WriteString("* BAD Invalid command\r\n")
			mc.writer.Flush()
			continue
		}

		tag := parts[0]
		command := strings.ToUpper(parts[1])

		// Check for authentication commands
		if command == "LOGIN" && len(parts) >= 4 {
			// Extract username and password
			username := strings.Trim(parts[2], "\"")
			password := strings.Trim(parts[3], "\"")

			// Parse username for server info
			if err := mc.parseUsername(username); err != nil {
				mc.writer.WriteString(fmt.Sprintf("%s NO %v\r\n", tag, err))
				mc.writer.Flush()
				return
			}

			// Connect to real server
			if err := mc.connectToServer(mp.TLSConfig, mp.DefaultRemotePort); err != nil {
				mc.writer.WriteString(fmt.Sprintf("%s NO Failed to connect to server: %v\r\n", tag, err))
				mc.writer.Flush()
				return
			}

			// Read server greeting
			serverGreeting, err := mc.serverReader.ReadString('\n')
			if err != nil {
				mc.writer.WriteString(fmt.Sprintf("%s NO Failed to read server greeting\r\n", tag))
				mc.writer.Flush()
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
				mc.writer.WriteString(fmt.Sprintf("%s NO Authentication failed\r\n", tag))
				mc.writer.Flush()
				return
			}

			// Forward response to client
			mc.writer.WriteString(response)
			mc.writer.Flush()

			// Check if authentication succeeded
			if strings.Contains(response, tag+" OK") {
				mc.authenticated = true
				if mp.Debug {
					log.Printf("[%s] Successfully authenticated to %s", mc.id, mc.targetServer)
				}

				// Switch to transparent proxy mode
				mc.transparentProxy()
				return
			}

			// Authentication failed
			return

		} else if command == "AUTHENTICATE" && len(parts) >= 3 {
			authType := strings.ToUpper(parts[2])
			if authType == "PLAIN" {
				// Send continuation response
				mc.writer.WriteString("+ \r\n")
				mc.writer.Flush()

				// Read base64 encoded credentials
				credLine, err := mc.reader.ReadString('\n')
				if err != nil {
					mc.writer.WriteString(fmt.Sprintf("%s NO Authentication failed\r\n", tag))
					mc.writer.Flush()
					return
				}

				// Decode credentials
				decoded, err := decodeBase64(strings.TrimSpace(credLine))
				if err != nil {
					mc.writer.WriteString(fmt.Sprintf("%s NO Invalid credentials encoding\r\n", tag))
					mc.writer.Flush()
					return
				}

				// AUTH PLAIN format: \0username\0password
				parts := strings.Split(decoded, "\x00")
				if len(parts) != 3 {
					mc.writer.WriteString(fmt.Sprintf("%s NO Invalid AUTH PLAIN format\r\n", tag))
					mc.writer.Flush()
					return
				}

				username := parts[1]
				password := parts[2]

				// Parse username for server info
				if err := mc.parseUsername(username); err != nil {
					mc.writer.WriteString(fmt.Sprintf("%s NO %v\r\n", tag, err))
					mc.writer.Flush()
					return
				}

				// Connect to real server
				if err := mc.connectToServer(mp.TLSConfig, mp.DefaultRemotePort); err != nil {
					mc.writer.WriteString(fmt.Sprintf("%s NO Failed to connect to server: %v\r\n", tag, err))
					mc.writer.Flush()
					return
				}

				// Read server greeting
				serverGreeting, err := mc.serverReader.ReadString('\n')
				if err != nil {
					mc.writer.WriteString(fmt.Sprintf("%s NO Failed to read server greeting\r\n", tag))
					mc.writer.Flush()
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
					mc.writer.WriteString(fmt.Sprintf("%s NO Server rejected authentication\r\n", tag))
					mc.writer.Flush()
					return
				}

				// Send real credentials
				realCreds := encodeBase64(fmt.Sprintf("\x00%s\x00%s", mc.realUsername, password))
				mc.serverWriter.WriteString(realCreds + "\r\n")
				mc.serverWriter.Flush()

				// Read response
				response, err := mc.readIMAPResponse(tag)
				if err != nil {
					mc.writer.WriteString(fmt.Sprintf("%s NO Authentication failed\r\n", tag))
					mc.writer.Flush()
					return
				}

				// Forward response to client
				mc.writer.WriteString(response)
				mc.writer.Flush()

				// Check if authentication succeeded
				if strings.Contains(response, tag+" OK") {
					mc.authenticated = true
					if mp.Debug {
						log.Printf("[%s] Successfully authenticated to %s", mc.id, mc.targetServer)
					}

					// Switch to transparent proxy mode
					mc.transparentProxy()
					return
				}

				// Authentication failed
				return
			} else {
				mc.writer.WriteString(fmt.Sprintf("%s NO Unsupported authentication mechanism\r\n", tag))
				mc.writer.Flush()
			}

		} else if command == "CAPABILITY" {
			// Respond with basic capabilities
			mc.writer.WriteString("* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN\r\n")
			mc.writer.WriteString(fmt.Sprintf("%s OK CAPABILITY completed\r\n", tag))
			mc.writer.Flush()

		} else if command == "NOOP" {
			mc.writer.WriteString(fmt.Sprintf("%s OK NOOP completed\r\n", tag))
			mc.writer.Flush()

		} else if command == "LOGOUT" {
			mc.writer.WriteString("* BYE LiquidProxy logging out\r\n")
			mc.writer.WriteString(fmt.Sprintf("%s OK LOGOUT completed\r\n", tag))
			mc.writer.Flush()
			return

		} else {
			// Before authentication, reject other commands
			mc.writer.WriteString(fmt.Sprintf("%s NO Please authenticate first\r\n", tag))
			mc.writer.Flush()
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
