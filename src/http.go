package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// checkRedirect checks if the request URL matches any redirect rules and returns the target URL
func checkRedirect(reqURL *url.URL) (*url.URL, bool) {
	redirectMutex.RLock()
	defer redirectMutex.RUnlock()

	// Check if domain has any redirect rules
	rules, exists := redirectRules[reqURL.Host]
	if !exists {
		return nil, false
	}

	// Build the full URL string for comparison
	fullURL := reqURL.String()

	// Check each rule for the domain
	for _, rule := range rules {
		fromPrefix := rule.fromURL.String()
		if strings.HasPrefix(fullURL, fromPrefix) {
			// Apply the redirect, preserving the path suffix
			suffix := strings.TrimPrefix(fullURL, fromPrefix)

			// Parse the target URL and append the suffix properly
			targetURL, _ := url.Parse(rule.toURL.String())
			if targetURL != nil {
				// If suffix contains a query string, handle it properly
				if idx := strings.Index(suffix, "?"); idx >= 0 {
					targetURL.Path = targetURL.Path + suffix[:idx]
					targetURL.RawQuery = suffix[idx+1:]
				} else {
					targetURL.Path = targetURL.Path + suffix
				}
			}
			return targetURL, true
		}
	}

	return nil, false
}

// loadRedirectRules loads URL redirect rules from redirects.txt
func loadRedirectRules() error {
	redirectFile := "redirects.txt"

	// Check if file exists
	if _, err := os.Stat(redirectFile); os.IsNotExist(err) {
		log.Println("Warning: no redirects.txt file found")
		return nil
	}

	file, err := os.Open(redirectFile)
	if err != nil {
		return fmt.Errorf("failed to open redirects file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	var fromURL *url.URL

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		// Parse URL
		u, err := url.Parse(line)
		if err != nil {
			log.Printf("Warning: Invalid URL on line %d: %s", lineNum, line)
			continue
		}

		// Ensure URL has a scheme
		if u.Scheme == "" {
			log.Printf("Warning: URL missing scheme on line %d: %s", lineNum, line)
			continue
		}

		if fromURL == nil {
			// This is a "from" URL
			fromURL = u
		} else {
			// This is a "to" URL, create the redirect rule
			rule := redirectRule{
				fromURL: fromURL,
				toURL:   u,
			}

			// Extract domain from fromURL
			domain := fromURL.Host

			redirectMutex.Lock()
			redirectRules[domain] = append(redirectRules[domain], rule)
			redirectDomains[domain] = true
			redirectMutex.Unlock()

			// Reset for next pair
			fromURL = nil
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading redirects file: %w", err)
	}

	if fromURL != nil {
		log.Printf("Warning: Incomplete redirect rule (missing target URL) for: %s", fromURL.String())
	}

	return nil
}

// loadExclusionRules loads URLs to never MITM from no-mitm.txt
func loadExclusionRules() error {
	exclusionFile := "no-mitm.txt"

	// Check if file exists
	if _, err := os.Stat(exclusionFile); os.IsNotExist(err) {
		log.Println("Warning: no no-mitm.txt file found")
		return nil
	}

	file, err := os.Open(exclusionFile)
	if err != nil {
		return fmt.Errorf("failed to open exclusion file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse URL or domain
		if strings.Contains(line, "://") {
			// It's a full URL, extract the domain
			u, err := url.Parse(line)
			if err != nil {
				log.Printf("Warning: Invalid URL on line %d: %s", lineNum, line)
				continue
			}

			if u.Host != "" {
				excludedMutex.Lock()
				excludedDomains[u.Host] = true
				excludedMutex.Unlock()
				log.Printf("Excluding domain from MITM: %s", u.Host)
			}
		} else {
			// It's just a domain
			domain := line
			// Remove port if present
			if h, _, err := net.SplitHostPort(domain); err == nil {
				domain = h
			}

			excludedMutex.Lock()
			excludedDomains[domain] = true
			excludedMutex.Unlock()
			log.Printf("Excluding domain from MITM: %s", domain)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading exclusion file: %w", err)
	}

	return nil
}

func httpMain(systemRoots *x509.CertPool, ca tls.Certificate) {
	// Load redirect rules
	if err := loadRedirectRules(); err != nil {
		log.Printf("Error loading redirect rules: %v", err)
	}

	// Load MITM exclusion rules
	if err := loadExclusionRules(); err != nil {
		log.Printf("Error loading exclusion rules: %v", err)
	}

	// Configure server side with relaxed security for old OS X clients
	tlsServerConfig := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	if *allowSSL {
		tlsServerConfig.MinVersion = tls.VersionSSL30
	} else {
		tlsServerConfig.MinVersion = tls.VersionTLS12
	}

	// Configure client side with secure connections but enable AIA chasing
	tlsClientConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // Maintain decent security for outbound
		RootCAs:    systemRoots,
		// Let Go use default secure cipher suites for outbound connections
		VerifyPeerCertificate: createCertVerifier(systemRoots),
		// Enable session tickets for upstream connections
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
	}

	p := &Proxy{
		CA:              &ca,
		TLSServerConfig: tlsServerConfig,
		TLSClientConfig: tlsClientConfig,
		FlushInterval:   100 * time.Millisecond,
		Wrap:            transparentProxy,
	}

	log.Printf("Liquid HTTP Proxy started on port %d", *httpPort)
	if *logURLs {
		log.Println("URL logging is ENABLED")
	}
	if *forceMITM {
		log.Println("Force MITM mode is ENABLED")
	}

	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(*httpPort), p))
}

func transparentProxy(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := fmt.Sprintf("%p", r)

		if *logURLs {
			log.Printf("[%s] HTTP URL: %s %s", reqID, r.Method, r.URL.String())
		}

		rw := &responseTracker{
			ResponseWriter: w,
			reqID:          reqID,
			url:            r.URL.String(),
		}

		upstream.ServeHTTP(rw, r)
	})
}

// responseTracker tracks response status and completion
type responseTracker struct {
	http.ResponseWriter
	reqID       string
	url         string
	status      int
	wroteHeader bool
}

func (rw *responseTracker) WriteHeader(statusCode int) {
	rw.wroteHeader = true
	rw.status = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseTracker) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// Proxy is a forward proxy that substitutes its own certificate
// for incoming TLS connections in place of the upstream server's
// certificate.
type Proxy struct {
	// Wrap specifies a function for optionally wrapping upstream for
	// inspecting the decrypted HTTP request and response.
	Wrap func(upstream http.Handler) http.Handler

	// CA specifies the root CA for generating leaf certs for each incoming
	// TLS request.
	CA *tls.Certificate

	// TLSServerConfig specifies the tls.Config to use when generating leaf
	// cert using CA.
	TLSServerConfig *tls.Config

	// TLSClientConfig specifies the tls.Config to use when establishing
	// an upstream connection for proxying.
	TLSClientConfig *tls.Config

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	FlushInterval time.Duration
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if r.URL.Host == lpHost1 || r.URL.Host == lpHost2 {
		serveWebUIPlain(w, r)
		return
	}

	if *blockRemoteConnections {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Invalid remote address", http.StatusBadRequest)
			return
		}

		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			http.Error(w, "Remote connections not allowed", http.StatusForbidden)
			return
		}
	}

	if r.Method == "CONNECT" {
		p.serveConnect(w, r)
		return
	}

	// Create a custom director that handles redirects transparently
	director := func(req *http.Request) {
		httpDirector(req)

		// Check for redirects and modify the request to go to the redirect target
		if targetURL, shouldRedirect := checkRedirect(req.URL); shouldRedirect {
			log.Printf("Redirecting %s → %s", req.URL.String(), targetURL.String())
			req.URL = targetURL
			req.Host = targetURL.Host
		}
	}

	// Create a custom transport that handles connection errors
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// First try to connect to the requested address
			conn, err := net.Dial(network, addr)
			if err != nil {
				// If connection fails, check if this is a redirect domain
				host, _, _ := net.SplitHostPort(addr)
				redirectMutex.RLock()
				rules, hasRedirects := redirectRules[host]
				redirectMutex.RUnlock()

				if hasRedirects && len(rules) > 0 {
					// Try the first redirect target
					targetHost := rules[0].toURL.Host
					targetPort := rules[0].toURL.Port()
					if targetPort == "" {
						if rules[0].toURL.Scheme == "https" {
							targetPort = "443"
						} else {
							targetPort = "80"
						}
					}
					targetAddr := net.JoinHostPort(targetHost, targetPort)

					return net.Dial(network, targetAddr)
				}
			}
			return conn, err
		},
		TLSClientConfig: p.TLSClientConfig,
	}

	rp := &httputil.ReverseProxy{
		Director:      director,
		Transport:     transport,
		FlushInterval: p.FlushInterval,
	}
	p.Wrap(rp).ServeHTTP(w, r)
}

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	var (
		name = dnsName(r.Host)
		host = r.Host
	)

	// Generate a unique ID for this connection
	connID := fmt.Sprintf("conn-%p", r)

	if name == "" {
		log.Printf("[%s] Cannot determine cert name for %s", connID, host)
		http.Error(w, "no upstream", 503)
		return
	}

	// Hijack the connection early
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[%s] ResponseWriter does not support hijacking", connID)
		http.Error(w, "internal server error", 500)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[%s] Failed to hijack connection: %v", connID, err)
		http.Error(w, "internal server error", 500)
		return
	}

	// Send 200 OK response
	if _, err = clientConn.Write(okHeader); err != nil {
		log.Printf("[%s] Failed to send 200 OK: %v", connID, err)
		clientConn.Close()
		return
	}

	// Peek at the ClientHello to determine routing
	clientHello, err := peekClientHello(clientConn)
	if err != nil {
		// Fall back to MITM mode if we can't parse the ClientHello
		p.serveMITM(clientConn, host, name, nil, connID)
		return
	}

	// Check if domain has redirect rules or is excluded from MITM
	// Extract domain without port
	domain := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		domain = h
	}

	redirectMutex.RLock()
	hasRedirects := redirectDomains[domain]
	redirectMutex.RUnlock()

	excludedMutex.RLock()
	isExcluded := excludedDomains[domain]
	excludedMutex.RUnlock()

	// Route based on client capabilities, redirect rules, and exclusion rules
	if isExcluded {
		// Domain is explicitly excluded from MITM - always use passthrough
		if *logURLs {
			log.Printf("[%s] Domain %s is excluded from MITM, using passthrough", connID, domain)
		}
		p.passthroughConnection(clientConn, host, clientHello, connID)
	} else if clientHello.isModernClient && !hasRedirects && !*forceMITM {
		// Modern client detected, no redirects, and force MITM not enabled - use passthrough mode
		p.passthroughConnection(clientConn, host, clientHello, connID)
	} else {
		// Legacy client OR domain has redirects OR force MITM enabled - use MITM mode
		p.serveMITM(clientConn, host, name, clientHello, connID)
	}
}

func (p *Proxy) cert(names ...string) (*tls.Certificate, error) {
	// Create a cache key from the domain names
	cacheKey := names[0]

	// Check if we have a cached certificate for this domain
	leafCertMutex.RLock()
	cachedCert, found := leafCertCache[cacheKey]
	leafCertMutex.RUnlock()

	if found {
		// Check if the certificate is still valid (has not expired)
		if time.Now().Before(cachedCert.Leaf.NotAfter) {
			// Create a defensive copy of the certificate to prevent shared state issues
			certCopy := new(tls.Certificate)
			*certCopy = *cachedCert
			return certCopy, nil
		}
		// Certificate expired, remove from cache
		leafCertMutex.Lock()
		delete(leafCertCache, cacheKey)
		leafCertMutex.Unlock()
	}

	// Generate a new certificate
	cert, err := genCert(p.CA, names)
	if err != nil {
		log.Printf("Error generating certificate for %s: %v", cacheKey, err)
		return nil, err
	}

	// Cache the new certificate
	leafCertMutex.Lock()
	leafCertCache[cacheKey] = cert
	leafCertMutex.Unlock()

	// Return a copy to prevent shared state issues
	certCopy := new(tls.Certificate)
	*certCopy = *cert
	return certCopy, nil
}

var okHeader = []byte("HTTP/1.1 200 OK\r\n\r\n")

func httpDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "http"
}

// passthroughConnection handles a connection in passthrough mode without TLS interception
func (p *Proxy) passthroughConnection(clientConn net.Conn, host string, clientHello *clientHelloInfo, connID string) {
	// Connect to the real server
	serverConn, err := net.Dial("tcp", host)
	if err != nil {
		log.Printf("[%s] Failed to connect to upstream host %s: %v", connID, host, err)
		clientConn.Close()
		return
	}

	// Send the ClientHello we already read to the server
	_, err = serverConn.Write(clientHello.raw)
	if err != nil {
		log.Printf("[%s] Failed to send ClientHello to server: %v", connID, err)
		serverConn.Close()
		clientConn.Close()
		return
	}

	// Set up bidirectional copying
	done := make(chan bool, 2)

	// Client to server
	go func() {
		copyData(serverConn, clientConn, connID, "Client→Server")
		// Half-close: signal EOF to server but keep reading
		if tcpConn, ok := serverConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		done <- true
	}()

	// Server to client
	go func() {
		copyData(clientConn, serverConn, connID, "Server→Client")
		// Half-close: signal EOF to client but keep reading
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		done <- true
	}()

	// Wait for both directions to complete
	<-done
	<-done

	// Now close both connections fully
	clientConn.Close()
	serverConn.Close()
}

// handleMITMWithLogging handles MITM connections with HTTP parsing and URL logging/redirects
func (p *Proxy) handleMITMWithLogging(tlsConn *tls.Conn, serverConn *tls.Conn, host, connID string, checkRedirects bool) {
	// Read HTTP requests from client and forward to server
	reader := bufio.NewReader(tlsConn)
	serverReader := bufio.NewReader(serverConn)

	for {
		// Read the request
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				log.Printf("[%s] Error reading request: %v", connID, err)
			}
			break
		}

		// Set up the request URL
		req.URL.Scheme = "https"
		if req.Host == "" {
			req.Host = host
		}
		req.URL.Host = req.Host

		// Log the URL if enabled
		if *logURLs {
			fullURL := fmt.Sprintf("https://%s%s", req.Host, req.URL.Path)
			if req.URL.RawQuery != "" {
				fullURL += "?" + req.URL.RawQuery
			}
			log.Printf("[%s] MITM URL: %s %s", connID, req.Method, fullURL)
		}

		// Check for redirects if enabled for this domain
		if checkRedirects {
			if targetURL, shouldRedirect := checkRedirect(req.URL); shouldRedirect {
				log.Printf("[%s] Redirecting %s → %s", connID, req.URL.String(), targetURL.String())

				// Update request to point to new URL
				req.URL = targetURL
				req.Host = targetURL.Host

				// If the target is on a different host, we need to proxy to it
				if targetURL.Host != host {
					// Create a new TLS connection to the target host
					var targetConfig *tls.Config
					if p.TLSClientConfig == nil {
						targetConfig = new(tls.Config)
					} else {
						targetConfig = p.TLSClientConfig
					}
					targetConfig.ServerName = targetURL.Host

					targetConn, err := tls.Dial("tcp", targetURL.Host+":443", targetConfig)
					if err != nil {
						// Send error response to client
						tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
						break
					}
					defer targetConn.Close()

					// Forward the request to the target
					err = req.Write(targetConn)
					if err != nil {
						log.Printf("[%s] Error forwarding request to redirect target: %v", connID, err)
						tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
						break
					}

					// Read response from target
					targetReader := bufio.NewReader(targetConn)
					resp, err := http.ReadResponse(targetReader, req)
					if err != nil {
						log.Printf("[%s] Error reading response from redirect target: %v", connID, err)
						tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
						break
					}

					// Forward response to client
					err = resp.Write(tlsConn)
					if err != nil {
						log.Printf("[%s] Error writing redirect response to client: %v", connID, err)
						resp.Body.Close()
						break
					}
					resp.Body.Close()

					// Continue to next request
					continue
				}
			}
		}

		// Forward request to server directly
		req.RequestURI = "" // Must be cleared for client requests

		// Write request to server
		err = req.Write(serverConn)
		if err != nil {
			log.Printf("[%s] Error writing request to server: %v", connID, err)
			// Send error response to client
			tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			break
		}

		// Read response from server
		resp, err := http.ReadResponse(serverReader, req)
		if err != nil {
			log.Printf("[%s] Error reading response from server: %v", connID, err)
			// Send error response to client
			tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			break
		}

		// Write response back to client
		err = resp.Write(tlsConn)
		if err != nil {
			log.Printf("[%s] Error writing response to client: %v", connID, err)
			resp.Body.Close()
			break
		}
		resp.Body.Close()

		// Check if connection should be closed
		if req.Close || resp.Close {
			break
		}
	}

	// Close connections
	tlsConn.Close()
	serverConn.Close()
}

// serveMITM handles a connection in MITM mode with TLS interception
func (p *Proxy) serveMITM(clientConn net.Conn, host, name string, clientHello *clientHelloInfo, connID string) {
	// Get certificate from cache or generate new one
	cert, err := p.cert(name)
	if err != nil {
		log.Printf("[%s] Certificate error for %s: %v", connID, name, err)
		clientConn.Close()
		return
	}

	var sConfig *tls.Config
	// Create TLS server config
	if p.TLSServerConfig == nil {
		sConfig = new(tls.Config)
	} else {
		sConfig = p.TLSServerConfig
	}
	sConfig.Certificates = []tls.Certificate{*cert}
	sConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// Only request a new cert if the ServerName differs from our initial one
		if hello.ServerName == name {
			return cert, nil
		}

		return p.cert(hello.ServerName)
	}

	// Create a connection that can replay the ClientHello
	var tlsConn *tls.Conn
	if clientHello != nil {
		// We have already read the ClientHello, so we need to create a special connection
		// that will replay it when the TLS handshake starts
		replayConn := &replayConn{
			Conn:   clientConn,
			buffer: bytes.NewBuffer(clientHello.raw),
		}
		tlsConn = tls.Server(replayConn, sConfig)
	} else {
		// No ClientHello was peeked, proceed normally
		tlsConn = tls.Server(clientConn, sConfig)
	}

	// Perform TLS handshake
	err = tlsConn.Handshake()
	if err != nil {
		//log.Printf("[%s] TLS handshake error: %v", connID, err)
		tlsConn.Close()
		return
	}

	// Set up client TLS config for upstream connection
	var cConfig *tls.Config
	if p.TLSClientConfig == nil {
		cConfig = new(tls.Config)
	} else {
		cConfig = p.TLSClientConfig
	}
	cConfig.ServerName = name

	if name == lpHost1 || name == lpHost2 {
		serveWebUITLS(tlsConn, host, name, clientHello, connID)
		return
	}

	// Connect to the real server
	serverConn, err := tls.Dial("tcp", host, cConfig)
	if err != nil {
		// Check if there are redirects for this domain
		domain := host
		if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			domain = h
		}

		redirectMutex.RLock()
		rules, hasRedirects := redirectRules[domain]
		redirectMutex.RUnlock()

		// If there are redirects, try connecting to the first redirect target
		if hasRedirects && len(rules) > 0 {
			// Get the first redirect rule's target host
			targetHost := rules[0].toURL.Host
			if targetHost != "" && targetHost != domain {
				// Add port if not present
				if _, _, err := net.SplitHostPort(targetHost); err != nil {
					targetHost = targetHost + ":443"
				}

				// Update TLS config for new host
				redirectConfig := cConfig
				redirectConfig.ServerName = rules[0].toURL.Host

				// Try connecting to redirect target
				redirectConn, redirectErr := tls.Dial("tcp", targetHost, redirectConfig)
				if redirectErr == nil {
					// Success! Use this connection
					serverConn = redirectConn
					err = nil
				}
			}
		}

		// If we still have an error (no redirects or redirect failed)
		if err != nil {
			// Only if there's a certificate error, retry to capture the chain
			var unknownAuthorityErr x509.UnknownAuthorityError
			if errors.As(err, &unknownAuthorityErr) {
				// Retry with InsecureSkipVerify to capture the chain
				var capturedChain []*x509.Certificate
				retryConfig := cConfig
				retryConfig.InsecureSkipVerify = true

				// Quick connection just to get the chain
				if retryConn, retryErr := tls.Dial("tcp", host, retryConfig); retryErr == nil {
					// tls.Dial returns a *tls.Conn directly
					capturedChain = retryConn.ConnectionState().PeerCertificates
					retryConn.Close()
					log.Printf("[%s] Failed to connect to upstream host %s: %v%s", name, connID, err, extractCertificateChainInfo(err, capturedChain))
				} else {
					log.Printf("[%s] Failed to connect to upstream host %s: %v", name, connID, err)
				}
			} else {
				log.Printf("[%s] Failed to connect to upstream host %s: %v", name, connID, err)
			}
			tlsConn.Close()
			return
		}
	}

	// Check if domain has redirect rules
	// Extract domain without port
	domain := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		domain = h
	}

	redirectMutex.RLock()
	hasRedirects := redirectDomains[domain]
	redirectMutex.RUnlock()

	// If URL logging is enabled OR domain has redirects, parse HTTP requests
	if *logURLs || hasRedirects {
		// Parse and handle HTTP requests
		p.handleMITMWithLogging(tlsConn, serverConn, host, connID, hasRedirects)
	} else {
		// Use efficient raw TCP/TLS forwarding
		done := make(chan bool, 2)

		// Client to server
		go func() {
			copyData(serverConn, tlsConn, connID, "Client→Server")
			done <- true
		}()

		// Server to client
		go func() {
			copyData(tlsConn, serverConn, connID, "Server→Client")
			done <- true
		}()

		// Wait for both directions to complete
		<-done
		<-done

		// Now close both connections
		tlsConn.Close()
		serverConn.Close()
	}
}
