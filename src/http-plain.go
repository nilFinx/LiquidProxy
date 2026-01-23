package liquidproxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
)

func transparentProxy(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isIPBanned(r.RemoteAddr) {
			w.WriteHeader(403)
			w.Write([]byte("Banned"))
		}
		if r.URL.Host == lpHost1 || r.URL.Host == lpHost2 {
			serveWebUIPlain(w, r)
			return
		}
		aExcludedMutex.RLock()
		isExcluded := aExcludedDomains[r.Host]
		aExcludedMutex.RUnlock()
		if !isExcluded && !isIPAllowed(r.RemoteAddr) && *proxyPassword != "" && !strings.HasSuffix(r.Host, "apple.com") {
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
				log.Printf("[%s] Got correct password (transparentProxy)", fmt.Sprintf("%p", r))
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

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
