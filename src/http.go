package liquidproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	httpPort      = flag.Int("http-port", 6531, "HTTP proxy port")
	disableHTTP   = flag.Bool("no-http", false, "Disable HTTP proxy")
	disableWebUI  = flag.Bool("no-webui", false, "Disable web UI for HTTP proxy")
	enforceCert   = flag.Bool("enforce-cert", false, "Enforce client cert on HTTP proxy (not recommended)")
	proxyPassword = flag.String("proxy-password", "", "HTTP proxy password in username:password format")
	forceMITM     = flag.Bool("force-mitm", false, "Force MITM mode for all HTTP proxy connections that isn't on no-mitm")
	logURLs       = flag.Bool("log-urls", false, "Print every URL accessed in MITM mode")

	// Redirect URLs
	redirectRules   = make(map[string][]redirectRule)
	redirectDomains = make(map[string]bool)

	// Exclude from MITM
	excludedDomains = make(map[string]bool)

	// No dial errors
	noDialErrorDomains = make(map[string]bool)

	// Exclude from authentication
	authExcludedDomains = make(map[string]bool)

	allowedIPs   = make(map[string]bool)
	allowedMutex sync.RWMutex

	clientCALeaf *x509.Certificate
)

func allowIP(ipmash string) {
	ip := unmashIP(ipmash)
	allowedMutex.RLock()
	allowedIPs[ip] = true
	allowedMutex.RUnlock()
	log.Printf("Allowing %s", ip)
}

func isIPAllowed(ipmash string) (result bool) {
	allowedMutex.RLock()
	result = allowedIPs[unmashIP(ipmash)]
	allowedMutex.RUnlock()
	return result
}

func httpMain(systemRoots *x509.CertPool, ca tls.Certificate, tlsServerConfig *tls.Config) {
	// redirect rules
	if err := loadRedirectRules(); err != nil {
		log.Printf("Error loading redirect rules: %v", err)
	}

	// MITM exclusion rules
	if err := loadURLRules("no-mitm.txt", excludedDomains); err != nil {
		log.Printf("Error loading exclusion rules: %v", err)
	}

	// No "dial error" rules
	if err := loadURLRules("no-dial-error.txt", noDialErrorDomains); err != nil {
		log.Printf("Error loading no dial error rules: %v", err)
	}

	// auth exclusion rules (deprecated)
	if _, err := os.Stat("bipas.txt"); os.IsExist(err) {
		log.Printf("Warning: bipas.txt is deprecated. Rename to auth-bypass.txt.")
	}
	if err := loadURLRules("bipas.txt", authExcludedDomains); err != nil {
		log.Printf("Error loading bipas rules: %v", err)
	}

	// auth exclusion rules
	if err := loadURLRules("auth-bypass.txt", authExcludedDomains); err != nil {
		log.Printf("Error loading auth-bypass rules: %v", err)
	}

	if *enforceCert {
		data, err := os.ReadFile(clientCAFile)
		if err != nil {
			log.Fatal(fmt.Errorf("%s\nCannot load cllient certificates. Did you really generate them?", err))
		}
		for {
			var block *pem.Block
			block, data = pem.Decode(data)
			if block == nil {
				break
			}

			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					log.Fatal(err)
				}
				clientCALeaf = cert
				break
			}
		}
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

	p := &HTTPProxy{
		CA:              &ca,
		TLSServerConfig: tlsServerConfig,
		TLSClientConfig: tlsClientConfig,
		FlushInterval:   100 * time.Millisecond,
		Wrap:            transparentHTTPProxy,
	}

	log.Printf("HTTP Proxy started (%d)", *httpPort)
	if *logURLs {
		log.Println("URL logging is ENABLED")
	}
	if *forceMITM {
		log.Println("Force MITM mode is ENABLED")
	}

	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(*httpPort), p))
}

func transparentHTTPProxy(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isIPBanned(r.RemoteAddr) {
			w.WriteHeader(403)
			w.Write([]byte("Banned"))
		}
		if !*disableWebUI && (r.URL.Host == lpHost1 || r.URL.Host == lpHost2) {
			serveWebUIPlain(w, r)
			return
		}
		isExcluded := authExcludedDomains[r.Host]
		if !(isExcluded || isIPAllowed(r.RemoteAddr) || (*proxyPassword == "" && !*enforceCert) || !strings.HasSuffix(r.Host, "apple.com")) {
			pauth := r.Header.Get("Proxy-Authorization")
			if pauth == "" {
				send407(w)
				return
			} else {
				ppassenc := encodeBase64(fmt.Sprintf("lp:%s", *proxyPassword))
				if pauth != ppassenc {
					log.Printf("[%s] Got invalid password on %s", r.RemoteAddr, r.Host)
					addFailedIP(r.RemoteAddr)
					send407(w)
					return
				}
				log.Printf("[%s] Got correct password (transparentHTTPProxy)", fmt.Sprintf("%p", r))
				allowIP(r.RemoteAddr)
			}
		}
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

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
				rules, hasRedirects := redirectRules[host]

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

func (p *HTTPProxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	var (
		name = dnsName(r.Host)
		host = r.Host
	)

	if isIPBanned(r.RemoteAddr) {
		w.WriteHeader(403)
		w.Write([]byte("Banned"))
		return
	}

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

	notAuthenticated := true
	if !*enforceCert && *proxyPassword != "" {
		isExcluded := authExcludedDomains[r.Host]
		if !(isExcluded || isIPAllowed(r.RemoteAddr) || strings.HasSuffix(r.Host, "apple.com")) {
			pauth := r.Header.Get("Proxy-Authorization")
			if pauth == "" {
				if _, err := clientConn.Write(authplsHeader); err != nil {
					log.Printf("[%s] Failed to send 407: %v", connID, err)
				}
				if *debug {
					log.Printf("[%s] Requesting auth (serveConnect)", connID)
				}
				clientConn.Close()
				return
			} else {
				ppassenc := encodeBase64(fmt.Sprintf("lp:%s", *proxyPassword))
				if pauth != "Basic "+ppassenc {
					log.Printf("[%s] Got invalid password on %s", r.RemoteAddr, r.Host)
					addFailedIP(r.RemoteAddr)
					if _, err := clientConn.Write(authplsHeader); err != nil {
						log.Printf("[%s] Failed to send 401: %v", connID, err)
					}
					clientConn.Close()
				}
				log.Printf("[%s] Got correct password (serveConnect)", connID)
				allowIP(r.RemoteAddr)
				notAuthenticated = false
			}
		} else {
			notAuthenticated = false
		}
	} else {
		if !*enforceCert {
			notAuthenticated = false
		}
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
		if !notAuthenticated {
			p.serveMITM(clientConn, host, name, nil, connID, false)
		}
		return
	}

	if clientHello.isModernClient && *blockModernConnections {
		return
	}

	// Check if domain has redirect rules or is excluded from MITM
	// Extract domain without port
	domain := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		domain = h
	}

	hasRedirects := redirectDomains[domain]

	isExcluded := excludedDomains[domain]

	// Route based on client capabilities, redirect rules, and exclusion rules
	if isExcluded {
		// Domain is explicitly excluded from MITM - always use passthrough
		if *logURLs && *debug {
			log.Printf("[%s] Domain %s is excluded from MITM, using passthrough", connID, domain)
		}
		p.passthroughConnection(clientConn, host, clientHello, connID, notAuthenticated)
	} else if clientHello.isModernClient && !hasRedirects && !*forceMITM {
		// Modern client detected, no redirects, and force MITM not enabled - use passthrough mode
		p.passthroughConnection(clientConn, host, clientHello, connID, notAuthenticated)
	} else {
		// Legacy client OR domain has redirects OR force MITM enabled - use MITM mode
		p.serveMITM(clientConn, host, name, clientHello, connID, notAuthenticated)
	}
}

// passthroughConnection handles a connection in passthrough mode without TLS interception
func (p *HTTPProxy) passthroughConnection(clientConn net.Conn, host string, clientHello *clientHelloInfo, connID string, notAuthenticated bool) {
	// Connect to the real server
	serverConn, err := net.Dial("tcp", host)
	if err != nil {
		a, _, _ := strings.Cut(host, ":")
		if *debug && !noDialErrorDomains[a] {
			log.Printf("[%s] Failed to connect to upstream host %s: %v", connID, host, err)
		}
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
func (p *HTTPProxy) handleMITMWithLogging(tlsConn *tls.Conn, serverConn *tls.Conn, host, connID string, checkRedirects bool) {
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
func (p *HTTPProxy) serveMITM(clientConn net.Conn, host, name string, clientHello *clientHelloInfo, connID string, notAuthenticated bool) {
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
		log.Printf("[%s] TLS handshake error: %v", connID, err)
		tlsConn.Close()
		return
	}

	if !*disableWebUI && (name == lpHost1 || name == lpHost2) {
		serveWebUITLS(tlsConn, host, name, clientHello, connID)
		return
	}

	if notAuthenticated {
		a, _, _ := strings.Cut(host, ":")
		isExcluded := authExcludedDomains[a]
		if !(isExcluded || isIPAllowed(tlsConn.RemoteAddr().String())) {
			connStat := tlsConn.ConnectionState()
			if len(connStat.PeerCertificates) == 0 {
				tlsConn.Write(authplsHeader)
				tlsConn.Close()
				clientConn.Close()
				log.Printf("[%s] Server enforces cert but not given", tlsConn.RemoteAddr())
				return
			} else {
				if !clientCALeaf.Equal(connStat.PeerCertificates[0]) {
					tlsConn.Close()
					clientConn.Close()
					log.Printf("[%s] Bad cert", tlsConn.RemoteAddr())
					return
				}
			}
			log.Printf("[%s] Cert pass (serveMITM)", connID)
			allowIP(tlsConn.RemoteAddr().String())
			notAuthenticated = false
		} else {
			notAuthenticated = false
		}
	}

	// Set up client TLS config for upstream connection
	var cConfig *tls.Config
	if p.TLSClientConfig == nil {
		cConfig = new(tls.Config)
	} else {
		cConfig = p.TLSClientConfig
	}
	cConfig.ServerName = name

	// Connect to the real server
	serverConn, err := tls.Dial("tcp", host, cConfig)
	if err != nil {
		// Check if there are redirects for this domain
		domain := host
		if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			domain = h
		}

		rules, hasRedirects := redirectRules[domain]

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
			a, _, _ := strings.Cut(host, ":")
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
					if *debug && !noDialErrorDomains[a] {
						log.Printf("[%s] Failed to connect to upstream host %s: %v%s", name, connID, err, extractCertificateChainInfo(err, capturedChain))
					}
				} else {
					if *debug && !noDialErrorDomains[a] {
						log.Printf("[%s] Failed to connect to upstream host %s: %v", name, connID, err)
					}
				}
			} else {
				if *debug && !noDialErrorDomains[a] {
					log.Printf("[%s] Failed to connect to upstream host %s: %v", name, connID, err)
				}
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

	hasRedirects := redirectDomains[domain]

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
