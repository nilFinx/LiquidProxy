package liquidproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	_ "embed"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
)

//go:embed getcertpage.html
var getCertPageFile []byte

func webuiProcess(r *http.Request) (code int, mimetype string, data []byte) {
	file := "getcertpage.html"
	mimetype = "text/html"
	code = 200

	switch r.URL.Path {
	case "/cert.pem":
		file = certFile
		mimetype = "application/octet-stream"
	case "/cert.cer":
		file = certFileCer
		mimetype = "application/octet-stream"
	default:
		return code, mimetype, getCertPageFile
	}

	data, err := os.ReadFile(file)
	if err != nil {
		log.Printf("Error reading cert file: %v", err)
		// Send error response to client
		code = 500
		mimetype = "text/plain"
		data = []byte("Internal Server Error")
	}

	return code, mimetype, data
}

func serveWebUIPlain(w http.ResponseWriter, r *http.Request) {
	if *logURLs {
		log.Printf("[%s] HTTP URL: %s %s", fmt.Sprintf("%p", r), r.Method, r.URL.String())
	}

	code, mimetype, data := webuiProcess(r)
	w.Header().Add("Content-Type", mimetype)
	w.Header().Add("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(code)
	_, err := io.Copy(w, bytes.NewReader(data))
	if err != nil {
		log.Printf("[%s] Error writing response to client: %v", r.RemoteAddr, err)
		return
	}
}

func serveWebUITLS(tlsConn *tls.Conn, host, name string, clientHello *clientHelloInfo, connID string) {
	// Read HTTP requests from client and forward to server
	reader := bufio.NewReader(tlsConn)

	// Read the request
	req, err := http.ReadRequest(reader)
	if err != nil {
		if err != io.EOF {
			log.Printf("[%s] Error reading request: %v", connID, err)
		}
		return
	}

	if *logURLs {
		fullURL := fmt.Sprintf("https://%s%s", req.Host, req.URL.Path)
		if req.URL.RawQuery != "" {
			fullURL += "?" + req.URL.RawQuery
		}
		log.Printf("[%s] MITM URL: %s %s", connID, req.Method, fullURL)
	}

	code, mimetype, data := webuiProcess(req)
	res := &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(bytes.NewReader(data)),
		Header:     http.Header{},
		ProtoMajor: 1,
	}
	defer res.Body.Close()
	res.Header.Add("Content-Type", mimetype)
	res.Header.Add("Content-Length", strconv.Itoa(len(data)))

	err = res.Write(tlsConn)
	if err != nil {
		log.Printf("[%s] Error writing response to client: %v", connID, err)
		return
	}
	tlsConn.Close()
}
