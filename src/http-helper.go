package liquidproxy

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
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
				//log.Printf("Excluding domain from MITM: %s", u.Host)
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
			//log.Printf("Excluding domain from MITM: %s", domain)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading exclusion file: %w", err)
	}

	return nil
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
