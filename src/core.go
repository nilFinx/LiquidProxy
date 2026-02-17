package liquidproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"syscall"
)

var (
	version = "1.3.3"

	showVersion            = flag.Bool("version", false, "Show version and quit")
	fail2banOn             = flag.Int("fail2ban-limit", 5, "Ban the IP when the count has been reached")
	blockRemoteConnections = flag.Bool("block-remote-connections", false, "Block connections from non-localhost addresses")
	blockModernConnections = flag.Bool("block-modern-connections", false, "Block connections from modern devices (with TLSv1.3 and HTTP/2)")

	allowSSL     = flag.Bool("allow-ssl", false, "Allow SSL 3.0 - TLSv1.1 (insecure)")
	allowOldTLS  = flag.Bool("alow-old-tls", false, "Allow TLSv1.0&1.1 (insecure)")
	RSAKeyLength = flag.Int("rsa-key-length", 2048, "RSA key length")

	cpuProfile = flag.Bool("cpu-profile", false, "Enable CPU profiling to legacy_proxy_cpu.prof")
	debug      = flag.Bool("debug", false, "Enable debug logging (mostly mail only)")

	keyFile          = "LiquidProxy-key.pem"
	certFile         = "LiquidProxy-cert.pem"
	certFileCer      = "LiquidProxy-cert.cer"
	clientCAFile     = "LiquidProxy-clientCert.pem"
	clientIdentFile  = "LiquidProxy-client.p12"
	clientConfigFile = "LiquidProxy.mobileconfig"

	lpHost1 = "liquidproxy.r.e.a.l"
	lpHost2 = "lp.r.e.a.l"

	// Pre-generated RSA keys for fast certificate generation
	keyPool = make(chan *rsa.PrivateKey, 20)

	cipherSuites = []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,      // iOS 6
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, // iOS 6
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,      // iOS 6
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, // iOS 6
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	}
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

	if *showVersion {
		print("Version " + version)
		os.Exit(0)
	}

	if *proxyPassword == "" && !*enforceCert {
		log.Printf("Warning: Password auth nor enforceCert is enforced")
	} else if !*enforceCert {
		log.Printf("Note: proxyPassword is HTTP-only. For all HTTPS connections, certificate will be used.")
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

	// Configure server side with relaxed security for old OS X clients
	tlsServerConfig := &tls.Config{
		CipherSuites: cipherSuites,
	}

	if *enforceCert {
		tlsServerConfig.ClientAuth = tls.RequestClientCert
	}
	if *allowSSL {
		tlsServerConfig.MinVersion = tls.VersionSSL30
	} else if *allowOldTLS {
		tlsServerConfig.MinVersion = tls.VersionTLS10
	} else {
		tlsServerConfig.MinVersion = tls.VersionTLS12
	}
	if *allowSSL && *allowOldTLS {
		log.Printf("Warning: -allow-ssl and -allow-tls is detected at the same time. Pick one. (currently using -allow-ssl only	)")
	}

	genericTCPProxyMain(systemRoots, ca, tlsServerConfig)

	mailMain(systemRoots, ca, tlsServerConfig)
	xmppMain(systemRoots, ca, tlsServerConfig)

	if !*disableHTTP {
		httpMain(systemRoots, ca, tlsServerConfig)
	} else {
		select {} // Keep the thread running
	}
}
