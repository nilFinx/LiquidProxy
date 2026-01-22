package liquidproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

const (
	caMaxAge   = 5 * 365 * 24 * time.Hour
	leafMaxAge = 24 * time.Hour
	caUsage    = x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	leafUsage = caUsage

	// TLS constants for parsing
	tlsHandshakeTypeClientHello   = 0x01
	tlsExtensionALPN              = 0x0010
	tlsExtensionSupportedVersions = 0x002b

	tlsVersion10 = 0x0301
	tlsVersion11 = 0x0302
	tlsVersion12 = 0x0303
	tlsVersion13 = 0x0304
)

func isSnowLeopard() bool {
	cmd := exec.Command("sw_vers", "-productVersion")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	version := strings.TrimSpace(string(output))
	// Snow Leopard is 10.6.x
	// No shit
	return strings.HasPrefix(version, "10.6.")
}

func loadSystemCertPool() (*x509.CertPool, error) {
	// Try the standard method first (unless we're on Snow Leopard)
	if !isSnowLeopard() {
		systemRoots, err := x509.SystemCertPool()
		if err == nil && systemRoots != nil {
			return systemRoots, nil
		}
	}

	// Fallback: Use security command to export certificates. Needed on Snow Leopard.
	log.Println("Using security to load system certificates.")

	pool := x509.NewCertPool()
	keychains := []string{
		"", // empty string for default keychain search list
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Library/Keychains/System.keychain",
	}

	// Load from all keychains
	for _, keychain := range keychains {
		args := []string{"find-certificate", "-a", "-p"}
		if keychain != "" {
			args = append(args, keychain)
		}

		cmd := exec.Command("security", args...)
		output, err := cmd.Output()
		if err != nil {
			if keychain != "" {
				log.Printf("Warning: Failed to load certificates from %s: %v", keychain, err)
			}
			continue
		}

		// Parse the PEM output
		for len(output) > 0 {
			block, rest := pem.Decode(output)
			if block == nil {
				break
			}
			output = rest

			if block.Type != "CERTIFICATE" {
				continue
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}

			pool.AddCert(cert)
		}
	}

	if len(pool.Subjects()) == 0 {
		log.Fatal("Failed to load any certificates from system keychains")
	}

	return pool, nil
}

// ClientHello detection structures
type clientHelloInfo struct {
	raw            []byte
	tlsVersion     uint16
	alpnProtocols  []string
	supportsTLS13  bool
	supportsHTTP2  bool
	isModernClient bool
}

// redirectRule represents a URL redirect rule
type redirectRule struct {
	fromURL *url.URL
	toURL   *url.URL
}

// parseClientHello parses a TLS ClientHello message to detect modern TLS features
func parseClientHello(data []byte) (*clientHelloInfo, error) {
	info := &clientHelloInfo{
		raw: data,
	}

	// Minimum size check: 5 bytes for TLS record header + 4 bytes for handshake header
	if len(data) < 9 {
		return nil, fmt.Errorf("data too short to be ClientHello")
	}

	// Check TLS record header
	if data[0] != 0x16 { // Handshake record type
		return nil, fmt.Errorf("not a TLS handshake record")
	}

	// Skip TLS version from record header (backwards compatibility version)
	_ = uint16(data[1])<<8 | uint16(data[2])

	// Get record length
	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		return nil, fmt.Errorf("incomplete TLS record")
	}

	// Parse handshake message
	pos := 5
	if data[pos] != tlsHandshakeTypeClientHello {
		return nil, fmt.Errorf("not a ClientHello message")
	}

	// Skip handshake length (3 bytes)
	pos += 4

	// Get client version (2 bytes)
	if len(data) < pos+2 {
		return nil, fmt.Errorf("truncated ClientHello")
	}
	info.tlsVersion = uint16(data[pos])<<8 | uint16(data[pos+1])
	pos += 2

	// Skip client random (32 bytes)
	pos += 32

	// Skip session ID
	if len(data) < pos+1 {
		return nil, fmt.Errorf("truncated ClientHello at session ID")
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Skip cipher suites
	if len(data) < pos+2 {
		return nil, fmt.Errorf("truncated ClientHello at cipher suites")
	}
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen

	// Skip compression methods
	if len(data) < pos+1 {
		return nil, fmt.Errorf("truncated ClientHello at compression")
	}
	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	// Parse extensions if present
	if len(data) >= pos+2 {
		extensionsLen := int(data[pos])<<8 | int(data[pos+1])
		pos += 2

		if len(data) >= pos+extensionsLen {
			if err := parseExtensions(data[pos:pos+extensionsLen], info); err != nil {
				log.Printf("Error parsing extensions: %v", err)
			}
		}
	}

	// Determine if this is a modern client
	info.isModernClient = info.supportsTLS13 || info.supportsHTTP2

	return info, nil
}

// parseExtensions parses TLS extensions looking for ALPN and supported versions
func parseExtensions(data []byte, info *clientHelloInfo) error {
	pos := 0

	for pos+4 <= len(data) {
		extType := uint16(data[pos])<<8 | uint16(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if pos+extLen > len(data) {
			return fmt.Errorf("truncated extension")
		}

		extData := data[pos : pos+extLen]

		switch extType {
		case tlsExtensionALPN:
			parseALPN(extData, info)
		case tlsExtensionSupportedVersions:
			parseSupportedVersions(extData, info)
		}

		pos += extLen
	}

	return nil
}

// parseALPN parses the ALPN extension to detect HTTP/2 support
func parseALPN(data []byte, info *clientHelloInfo) {
	if len(data) < 2 {
		return
	}

	protocolListLen := int(data[0])<<8 | int(data[1])
	pos := 2

	for pos < 2+protocolListLen && pos < len(data) {
		protoLen := int(data[pos])
		pos++

		if pos+protoLen <= len(data) {
			proto := string(data[pos : pos+protoLen])
			info.alpnProtocols = append(info.alpnProtocols, proto)

			if proto == "h2" {
				info.supportsHTTP2 = true
			}
		}

		pos += protoLen
	}
}

// parseSupportedVersions parses the supported_versions extension to detect TLS 1.3
func parseSupportedVersions(data []byte, info *clientHelloInfo) {
	if len(data) < 1 {
		return
	}

	// For ClientHello, this is a list
	listLen := int(data[0])
	pos := 1

	for i := 0; i < listLen/2 && pos+2 <= len(data); i++ {
		version := uint16(data[pos])<<8 | uint16(data[pos+1])
		if version == tlsVersion13 {
			info.supportsTLS13 = true
		}
		pos += 2
	}
}

// peekClientHello peeks at the beginning of a connection to read the ClientHello
func peekClientHello(conn net.Conn) (*clientHelloInfo, error) {
	// We need to peek at enough data to parse the ClientHello
	// Maximum size is 16KB for the TLS record
	buf := make([]byte, 16384)

	// Set a short read timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read ClientHello: %w", err)
	}

	// Parse the ClientHello
	info, err := parseClientHello(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ClientHello: %w", err)
	}

	// Store the exact bytes we read
	info.raw = buf[:n]

	return info, nil
}

// startKeyPool starts background generation of RSA keys
func startKeyPool() {
	// Start key generation in background
	go func() {

		for {
			// First check if the pool needs more keys
			if len(keyPool) >= cap(keyPool) {
				// Pool is full, wait before checking again
				time.Sleep(1 * time.Second)
				continue
			}

			// Generate a new RSA key only when needed
			key, err := rsa.GenerateKey(rand.Reader, RSAKeyLength)
			if err != nil {
				log.Printf("Error pre-generating RSA key: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}

			// Add the key to the pool
			keyPool <- key
		}
	}()
}

// getKey gets an RSA key from the pool or generates one if needed
func getKey() (*rsa.PrivateKey, error) {
	// Try to get a key from the pool with a short timeout
	select {
	case key := <-keyPool:
		return key, nil
	default:
		// Immediately generate a key if none available
		return rsa.GenerateKey(rand.Reader, RSAKeyLength)
	}
}

// getIntermediateCerts retrieves cached certificates for the provided pool
func getIntermediateCerts(pool *x509.CertPool) {
	aiaCacheMutex.RLock()
	defer aiaCacheMutex.RUnlock()

	for _, cert := range aiaCertCache {
		pool.AddCert(cert)
	}
}

// createCertVerifier returns a function that verifies certificates and performs AIA chasing
// rootCAs should include both system roots and our generated CA certificate
func createCertVerifier(rootCAs *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// Convert raw certificates
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, asn1Data := range rawCerts {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				return err
			}
			certs[i] = cert
		}

		// Try standard verification first
		intermediatePool := x509.NewCertPool()

		// Add any certificates we've previously fetched via AIA
		getIntermediateCerts(intermediatePool)

		// Add all but the first cert as intermediates
		for _, cert := range certs[1:] {
			intermediatePool.AddCert(cert)
		}

		opts := x509.VerifyOptions{
			Roots:         rootCAs,
			Intermediates: intermediatePool,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}

		_, err := certs[0].Verify(opts)
		if err == nil {
			return nil
		}

		// If verification failed, try AIA chasing
		// AIA certificates are already cached in the chaseAIA function
		_, chainErr := chaseAIA(certs, rootCAs)
		if chainErr == nil {
			return nil
		}

		// If still failing, log the missing root cert info
		var unknownAuthorityErr x509.UnknownAuthorityError
		if errors.As(err, &unknownAuthorityErr) {
			certInfo := extractCertificateChainInfo(err, certs)
			if certInfo != "" {
				log.Printf("Certificate verification failed: %v%s", err, certInfo)
			}
		}

		return err
	}
}

// chaseAIA follows AIA URLs to download missing certificates
// rootCAs contains both system roots from macOS Keychain and our custom CA
func chaseAIA(certs []*x509.Certificate, rootCAs *x509.CertPool) ([]*x509.Certificate, error) {
	var downloadedCerts []*x509.Certificate
	intermediates := x509.NewCertPool()

	// Add all but the first cert as intermediates
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	// Check if we need to chase AIAs
	leaf := certs[0]
	for _, url := range leaf.IssuingCertificateURL {
		// Check if we've already fetched this certificate by url
		cacheKey := url

		aiaCacheMutex.RLock()
		cachedCert, found := aiaCertCache[cacheKey]
		aiaCacheMutex.RUnlock()

		if found {
			intermediates.AddCert(cachedCert)
			downloadedCerts = append(downloadedCerts, cachedCert)
			continue
		}

		resp, err := http.Get(url)
		if err != nil || resp.StatusCode != http.StatusOK {
			log.Println("Failed to fetch AIA certificate:", err)
			continue
		}

		certData, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Println("Failed to read AIA certificate:", err)
			continue
		}

		aiaCert, err := x509.ParseCertificate(certData)
		if err != nil {
			// Try parsing as PEM
			block, _ := pem.Decode(certData)
			if block == nil {
				log.Println("Failed to parse AIA certificate:", err)
				continue
			}

			aiaCert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Println("Failed to parse AIA certificate from PEM:", err)
				continue
			}
		}

		// Cache the certificate by URL
		aiaCacheMutex.Lock()
		aiaCertCache[cacheKey] = aiaCert
		aiaCacheMutex.Unlock()

		intermediates.AddCert(aiaCert)
		downloadedCerts = append(downloadedCerts, aiaCert)

		// Recursively check if this cert has AIAs too
		if len(aiaCert.IssuingCertificateURL) > 0 {
			moreCerts, _ := chaseAIA([]*x509.Certificate{aiaCert}, rootCAs)
			downloadedCerts = append(downloadedCerts, moreCerts...)
			for _, c := range moreCerts {
				intermediates.AddCert(c)
			}
		}
	}

	opts := x509.VerifyOptions{
		Roots:         rootCAs,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := leaf.Verify(opts)
	return downloadedCerts, err
}

func loadCA() (cert tls.Certificate, err error) {
	// Only load existing certificates
	cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return cert, fmt.Errorf("could not load certificate files (%s, %s): %w", certFile, keyFile, err)
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return cert, fmt.Errorf("could not parse certificate: %w", err)
	}

	return
}

// dnsName returns the DNS name in addr, if any.
func dnsName(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

func genCert(ca *tls.Certificate, names []string) (*tls.Certificate, error) {
	now := time.Now().Add(-1 * time.Hour).UTC()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             now,
		NotAfter:              now.Add(leafMaxAge),
		KeyUsage:              leafUsage,
		BasicConstraintsValid: true,
		DNSNames:              names,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	key, err := getKey()
	if err != nil {
		return nil, err
	}

	x, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Leaf, key.Public(), ca.PrivateKey)
	if err != nil {
		// If certificate generation fails, log detailed error message
		log.Printf("Certificate generation error: %v", err)
		log.Printf("Attempted to sign with CA subject: %s", ca.Leaf.Subject)
		return nil, err
	}

	cert := new(tls.Certificate)
	cert.Certificate = append(cert.Certificate, x)
	cert.PrivateKey = key
	cert.Leaf, _ = x509.ParseCertificate(x)
	return cert, nil
}

// extractCertificateChainInfo analyzes the certificate chain to identify the missing root
func extractCertificateChainInfo(err error, chain []*x509.Certificate) string {
	if err == nil || len(chain) == 0 {
		return ""
	}

	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		// Find the topmost certificate in the chain
		topCert := chain[len(chain)-1]

		// Check if it's self-signed (a root cert)
		if topCert.Subject.String() == topCert.Issuer.String() {
			// The root is in the chain but not trusted
			return fmt.Sprintf(" (untrusted root CA: %s)", topCert.Subject.CommonName)
		} else {
			// The chain is incomplete - missing the root
			return fmt.Sprintf(" (missing root CA: %s)", topCert.Issuer.CommonName)
		}
	}

	return ""
}
