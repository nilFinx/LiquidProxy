package liquidproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
)

var (
	version = "1.0.0"

	hostname, _ = os.Hostname()

	keyFile     = "LiquidProxy-key.pem"
	certFile    = "LiquidProxy-cert.pem"
	certFileCer = "LiquidProxy-cert.cer"

	lpHost1 = "liquidproxy.r.e.a.l"
	lpHost2 = "lp.r.e.a.l"

	// Generated certs are only used between the OS and the proxy. Prioritize speed.
	RSAKeyLength = 1024

	// Cache for certificates fetched via AIA
	aiaCertCache  = make(map[string]*x509.Certificate)
	aiaCacheMutex sync.RWMutex

	// Cache for generated leaf certificates
	leafCertCache = make(map[string]*tls.Certificate)
	leafCertMutex sync.RWMutex

	// Pre-generated RSA keys for fast certificate generation
	keyPool = make(chan *rsa.PrivateKey, 20)

	// Command line flags for HTTP proxy
	showVersion            = flag.Bool("version", false, "Show version and quit")
	proxyPassword          = flag.String("proxy-password", "", "Proxy password in username:password format")
	fail2banOn             = flag.Int("fail2ban-limit", 5, "Ban the IP when the count has been reached")
	forceMITM              = flag.Bool("force-mitm", false, "Force MITM mode for all connections")
	blockRemoteConnections = flag.Bool("block-remote-connections", false, "Block connections from non-localhost addresses")
	blockModernConnections = flag.Bool("block-modern-connections", false, "Block connections from modern devices (with TLSv1.3 and HTTP/2)")
	allowSSL               = flag.Bool("allow-ssl", false, "Allow SSL 3.0 - TLSv1.1 (insecure)")
	cpuProfile             = flag.Bool("cpu-profile", false, "Enable CPU profiling to legacy_proxy_cpu.prof")
	logURLs                = flag.Bool("log-urls", false, "Print every URL accessed in MITM mode")
	debug                  = flag.Bool("debug", false, "Enable debug logging (mail only)")
	httpPort               = flag.Int("http-port", 6531, "HTTP proxy port")
	imapPort               = flag.Int("imap-port", 6532, "IMAP proxy port")
	smtpPort               = flag.Int("smtp-port", 6533, "SMTP proxy port")
	disableHTTP            = flag.Bool("no-http", false, "Disable HTTP proxy")
	disableIMAP            = flag.Bool("no-imap", false, "Disable IMAP proxy")
	disableSMTP            = flag.Bool("no-smtp", false, "Disable SMTP proxy")

	// URL redirect configuration
	redirectRules   = make(map[string][]redirectRule)
	redirectDomains = make(map[string]bool)
	redirectMutex   sync.RWMutex

	// MITM exclusion configuration
	excludedDomains = make(map[string]bool)
	excludedMutex   sync.RWMutex
)

func FileCheck(file string) {
	if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
		log.Fatalf("%s does not exist. Make sure that %s, %s and %s exists.", file, keyFile, certFile, certFileCer)
	}
}

func Run() {
	// Read flags from flags.txt if it exists
	if data, err := os.ReadFile("flags.txt"); err == nil {
		flags := strings.Fields(string(data))
		os.Args = append([]string{os.Args[0]}, append(flags, os.Args[1:]...)...)
	}
	flag.Parse()

	log.Printf(*proxyPassword)

	if *showVersion {
		print("Version " + version)
		os.Exit(0)
	}

	if *proxyPassword == "" {
		log.Printf("Warning: Password auth not enforced")
	}

	FileCheck(keyFile)
	FileCheck(certFile)

	// Setup CPU profiling if requested
	if *cpuProfile {
		f, err := os.Create("legacy_proxy_cpu.prof")
		if err != nil {
			log.Fatal("Could not create CPU profile: ", err)
		}

		if err := pprof.StartCPUProfile(f); err != nil {
			f.Close()
			log.Fatal("Could not start CPU profile: ", err)
		}

		// Ensure profile is written on exit
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigs
			pprof.StopCPUProfile()
			f.Close()
			os.Exit(0)
		}()

		log.Println("CPU profiling enabled to legacy_proxy_cpu.prof")
	}

	// Start background key generation
	startKeyPool()

	ca, err := loadCA()
	if err != nil {
		log.Fatal("Error loading certificate:", err)
	}

	// Create a cert pool with system roots and our CA
	systemRoots, err := loadSystemCertPool()
	if err != nil {
		log.Fatal("Warning: Could not load system certificate pool:", err)
		systemRoots = x509.NewCertPool()
	}

	// Add our CA to the system roots
	systemRoots.AddCert(ca.Leaf)

	if !*blockRemoteConnections {
		log.Println("Remote connections are ALLOWED")
	}

	mailMain(systemRoots)
	if !*disableHTTP {
		httpMain(systemRoots, ca)
	} else {
		select {} // Keep the thread running
	}
}

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
