package main

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net"
	"strings"
)

// Helper functions for base64 encoding/decoding
func encodeBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func decodeBase64(s string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// transparentProxy switches to transparent proxy mode after authentication
func transparentProxy(id string, debug bool, tlsConn *tls.Conn, serverConn net.Conn) {
	if debug {
		log.Printf("[%s] Switching to transparent proxy mode", id)
	}

	// Verify connections are established
	if tlsConn == nil {
		if debug {
			log.Printf("[%s] ERROR: clientConn is nil in transparentProxy", id)
		}
		return
	}
	if serverConn == nil {
		if debug {
			log.Printf("[%s] ERROR: serverConn is nil in transparentProxy", id)
		}
		return
	}

	errc := make(chan error, 2)

	go func() {
		_, err := io.Copy(tlsConn, serverConn)
		errc <- err
	}()

	go func() {
		_, err := io.Copy(serverConn, tlsConn)
		errc <- err
	}()

	err2 := <-errc

	if debug {
		log.Printf("[%s] Close starting", id)
	}

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

	if debug && !ignore(err1) {
		log.Printf("[%s] copy error: %v", id, err1)
	}
	if debug && !ignore(err2) {
		log.Printf("[%s] copy error: %v", id, err2)
	}

	if debug {
		log.Printf("[%s] Goodbye!", id)
	}

	tlsConn.Close()
	serverConn.Close()
}
