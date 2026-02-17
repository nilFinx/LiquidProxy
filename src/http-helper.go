package liquidproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var okHeader = []byte("HTTP/1.1 200 OK\r\n\r\n")
var authplsHeader = []byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n")

// responseTracker tracks response status and completion
type responseTracker struct {
	http.ResponseWriter
	reqID       string
	url         string
	status      int
	wroteHeader bool
}

// redirectRule represents a URL redirect rule
type redirectRule struct {
	fromURL *url.URL
	toURL   *url.URL
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

func send407(w http.ResponseWriter) {
	w.Header().Add("Proxy-Authenticate", "Basic realm=\"proxy\"")
	w.WriteHeader(407)
	w.Write([]byte("Proxy requires auth"))
}

// checkRedirect checks if the request URL matches any redirect rules and returns the target URL
func checkRedirect(reqURL *url.URL) (*url.URL, bool) {

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

			redirectRules[domain] = append(redirectRules[domain], rule)
			redirectDomains[domain] = true

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
				excludedDomains[u.Host] = true
				if *debug {
					log.Printf("Excluding domain from MITM: %s", u.Host)
				}
			}
		} else {
			// It's just a domain
			domain := line
			// Remove port if present
			if h, _, err := net.SplitHostPort(domain); err == nil {
				domain = h
			}

			excludedDomains[domain] = true
			if *debug {
				log.Printf("Excluding domain from MITM: %s", domain)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading exclusion file: %w", err)
	}

	return nil
}

// loadBipasRules loads URLs to never ask for auth from bipas.txt
func loadBipasRules() error {
	bipasFile := "bipas.txt"

	// Check if file exists
	if _, err := os.Stat(bipasFile); os.IsNotExist(err) {
		log.Println("Warning: no bipas.txt file found")
		return nil
	}

	file, err := os.Open(bipasFile)
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
				authExcludedDomains[u.Host] = true
			}
		} else {
			// It's just a domain
			domain := line
			// Remove port if present
			if h, _, err := net.SplitHostPort(domain); err == nil {
				domain = h
			}

			authExcludedDomains[domain] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading bipas file: %w", err)
	}

	return nil
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

func httpDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "http"
}
