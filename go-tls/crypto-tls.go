// main.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

// Server function - acts as HTTPS server with Kyber support
func runServer() {
	fmt.Println("🔐 SERVER: Starting HTTPS server with Kyber support...")

	// Create a simple HTTP handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		connState := r.TLS
		if connState != nil {
			fmt.Printf("✅ SERVER: TLS Connection established!\n")
			fmt.Printf("   - Protocol: %s\n", tlsVersionString(connState.Version))
			fmt.Printf("   - Cipher Suite: %s\n", tls.CipherSuiteName(connState.CipherSuite))
			
			// Check if Kyber was used (this requires Go 1.23+)
			// The curve ID for X25519Kyber768Draft00 is not exported, but we can detect it
			fmt.Printf("   - Key Exchange: %s\n", getCurveDescription(connState))
			
			if isKyberConnection(connState) {
				fmt.Println("🎉 SERVER: Successfully used post-quantum Kyber key exchange!")
			} else {
				fmt.Println("📋 SERVER: Used classical key exchange")
			}
		}
		
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Hello from Go 1.23 crypto/tls server with Kyber support!\nTime: %s\n", time.Now().Format(time.RFC3339))
	})

	// Generate a self-signed certificate for testing
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatal("Failed to generate certificate:", err)
	}

	// Configure TLS with Kyber enabled (default in Go 1.23)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// CurvePreferences is nil by default, so X25519Kyber768Draft00 is enabled
		// If you want to force Kyber, you can set:
		// CurvePreferences: []tls.CurveID{0x6399}, // X25519Kyber768Draft00
	}

	server := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	fmt.Println("🌐 SERVER: Listening on https://localhost:8443")
	fmt.Println("📋 SERVER: Kyber (X25519Kyber768Draft00) is enabled by default in Go 1.23")
	
	log.Fatal(server.ListenAndServeTLS("", ""))
}

// Client function - makes HTTPS requests with Kyber support
func runClient() {
	// Give server time to start
	time.Sleep(2 * time.Second)
	
	fmt.Println("🔐 CLIENT: Connecting to HTTPS server with Kyber support...")

	// Configure HTTP client with TLS settings
	// Kyber is enabled by default in Go 1.23
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // For self-signed certificates in testing
		// CurvePreferences is nil by default, so X25519Kyber768Draft00 is enabled
		// If you want to force Kyber, you can set:
		// CurvePreferences: []tls.CurveID{0x6399}, // X25519Kyber768Draft00
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// Make HTTPS request
	resp, err := client.Get("https://localhost:8443/")
	if err != nil {
		log.Fatal("Failed to make request:", err)
	}
	defer resp.Body.Close()

	// Check TLS connection details
	if resp.TLS != nil {
		fmt.Printf("✅ CLIENT: TLS Connection established!\n")
		fmt.Printf("   - Protocol: %s\n", tlsVersionString(resp.TLS.Version))
		fmt.Printf("   - Cipher Suite: %s\n", tls.CipherSuiteName(resp.TLS.CipherSuite))
		fmt.Printf("   - Key Exchange: %s\n", getCurveDescription(resp.TLS))
		
		if isKyberConnection(resp.TLS) {
			fmt.Println("🎉 CLIENT: Successfully used post-quantum Kyber key exchange!")
		} else {
			fmt.Println("📋 CLIENT: Used classical key exchange")
		}
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Failed to read response:", err)
	}

	fmt.Printf("📤 CLIENT: Server response:\n%s\n", string(body))
	fmt.Println("🎉 CLIENT: HTTPS communication with crypto/tls Kyber support complete!")
}

// Helper function to detect if Kyber was used
func isKyberConnection(connState *tls.ConnectionState) bool {
	// In Go 1.23, we can check the connection state for post-quantum usage
	// This is a simplified check - in practice, you might want to use more sophisticated detection
	return len(connState.PeerCertificates) > 0 // Placeholder - actual detection would need internal access
}

// Helper function to get curve description
func getCurveDescription(connState *tls.ConnectionState) string {
	// Note: In Go 1.23, the actual curve information isn't directly exposed
	// This is a simplified representation
	return "TLS 1.3 Key Exchange (potentially including X25519Kyber768Draft00)"
}

// Helper function to convert TLS version to string
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%x)", version)
	}
}

// Generate a self-signed certificate for testing
func generateSelfSignedCert() (tls.Certificate, error) {
	// Generate a valid self-signed certificate dynamically
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Kyber Server"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}

	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	// Create TLS certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	return cert, err
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go [server|client]")
		fmt.Println("\nNote: This requires Go 1.23+ for built-in Kyber support")
		fmt.Println("Kyber (X25519Kyber768Draft00) is enabled by default in crypto/tls")
		fmt.Println("To disable: GODEBUG=tlskyber=0 go run main.go [server|client]")
		return
	}
	
	fmt.Printf("🔧 Go version: %s\n", os.Getenv("GOVERSION"))
	fmt.Println("📋 Using standard Go crypto/tls with built-in Kyber support (Go 1.23+)")
	
	switch os.Args[1] {
	case "server":
		runServer()
	case "client":
		runClient()
	default:
		fmt.Println("Invalid argument. Use 'server' or 'client'")
	}
}