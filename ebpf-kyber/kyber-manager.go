// kyber_sockops_manager.go - Integration of Kyber with sockops eBPF
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -package main KyberSockops sockops/crypto-ebpf.c -- -I. -O2 -Wall

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/Satyam-git-hub/kyber/ebpf-kyber/genpkg"
	
)

// Message types (from your original Kyber implementation)
const (
	MSG_PUBLIC_KEY     = "PUBLIC_KEY"
	MSG_CIPHERTEXT     = "CIPHERTEXT"
	MSG_ENCRYPTED_DATA = "ENCRYPTED_DATA"
)

// Kyber Sockops Manager
type KyberSockopsManager struct {
	objs              *genpkg.KyberSockopsObjects
	cgroupLink        link.Link
	containerName     string
	cgroupPath        string
	activeConnections map[genpkg.KyberSockopsSockKey]*genpkg.KyberSockopsCryptoState
}

// Create new Kyber sockops manager
func NewKyberSockopsManager(containerName string) (*KyberSockopsManager, error) {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %v", err)
	}

	return &KyberSockopsManager{
		containerName:     containerName,
		activeConnections: make(map[genpkg.KyberSockopsSockKey]*genpkg.KyberSockopsCryptoState),
	}, nil
}

// Find container cgroup path
func (m *KyberSockopsManager) findContainerCgroup() error {
	// Execute the fetch-container-cgroup.sh script
	cmd := exec.Command("./fetch-container-cgroup.sh", m.containerName)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get container cgroup: %v", err)
	}

	// Parse the output to extract cgroup path
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "/sys/fs/cgroup") {
			// Extract the full path
			if strings.HasPrefix(line, "/sys/fs/cgroup") {
				m.cgroupPath = strings.TrimSpace(line)
				break
			}
			// Or extract from environment variable line
			if strings.Contains(line, "export") && strings.Contains(line, "_CGROUP_PATH=") {
				parts := strings.Split(line, "\"")
				if len(parts) >= 2 {
					m.cgroupPath = parts[1]
					break
				}
			}
		}
	}

	if m.cgroupPath == "" {
		return fmt.Errorf("could not find cgroup path for container %s", m.containerName)
	}

	fmt.Printf("📁 Found container cgroup: %s\n", m.cgroupPath)
	return nil
}

// Load and attach eBPF programs
func (m *KyberSockopsManager) LoadAndAttach() error {
	// Find container cgroup first
	if err := m.findContainerCgroup(); err != nil {
		return err
	}

	// Load eBPF objects
	objs := genpkg.KyberSockopsObjects{}
	if err := genpkg.LoadKyberSockopsObjects(&objs, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %v", err)
	}
	m.objs = &objs

	// Initialize configuration
	config := genpkg.KyberSockopsCryptoConfig{
		EnableEncryption: 1,
		EnableDecryption: 1,
		DebugMode:        1,
	}
	
	configKey := uint32(0)
	if err := m.objs.ConfigMap.Put(&configKey, &config); err != nil {
		return fmt.Errorf("failed to set config: %v", err)
	}

	// Initialize stats
	stats := genpkg.KyberSockopsCryptoStats{}
	if err := m.objs.StatsMap.Put(&configKey, &stats); err != nil {
		return fmt.Errorf("failed to initialize stats: %v", err)
	}

	// Attach sockops program to container cgroup
	cgroupLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    m.cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: m.objs.SockopsCrypto,
	})
	if err != nil {
		return fmt.Errorf("failed to attach sockops to cgroup %s: %v", m.cgroupPath, err)
	}
	m.cgroupLink = cgroupLink

	// For sk_msg program, we need to use RawAttachProgram instead of AttachMap
	// AttachMap is deprecated/not available in newer versions
	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  m.objs.SockMap.FD(),
		Program: m.objs.SkMsgCrypto,
		Attach:  ebpf.AttachSkMsgVerdict,
	})
	if err != nil {
		cgroupLink.Close()
		return fmt.Errorf("failed to attach sk_msg to sock_map: %v", err)
	}
	// Note: RawAttachProgram doesn't return a link object to store

	fmt.Printf("✅ Kyber sockops programs attached to container %s\n", m.containerName)
	fmt.Printf("   Cgroup: %s\n", m.cgroupPath)
	
	return nil
}

// Add Kyber-derived crypto state for a connection
func (m *KyberSockopsManager) AddKyberCryptoState(localIP net.IP, localPort int, 
	kyberSharedSecret []byte) error {
	
	// Create socket key
	sockKey := genpkg.KyberSockopsSockKey{
		Ip:   ipToUint32(localIP),
		Port: uint32(localPort),
	}

	// Derive AES key from Kyber shared secret
	aesKey := deriveAESKeyFromKyber(kyberSharedSecret)

	// Create crypto state
	cryptoState := &genpkg.KyberSockopsCryptoState{
		PacketCounter: 0,
		Active:        1,
	}

	// Copy Kyber secret and derived AES key
	copy(cryptoState.KyberSharedSecret[:], kyberSharedSecret)
	copy(cryptoState.AesKey[:], aesKey)

	// Initialize counters
	cryptoState.EncryptCounter[0] = 0x01
	cryptoState.DecryptCounter[0] = 0x02

	// Add to eBPF map
	if err := m.objs.CryptoStateMap.Put(&sockKey, cryptoState); err != nil {
		return fmt.Errorf("failed to add crypto state to eBPF map: %v", err)
	}

	// Track locally
	m.activeConnections[sockKey] = cryptoState

	fmt.Printf("🔑 Added Kyber crypto state for %s:%d\n", localIP.String(), localPort)
	fmt.Printf("   Kyber secret: %x...\n", kyberSharedSecret[:16])
	fmt.Printf("   AES key: %x...\n", aesKey[:16])

	return nil
}

// Kyber key exchange server
func (m *KyberSockopsManager) RunKyberServer(port int) error {
	fmt.Printf("🔐 Starting Kyber server on port %d...\n", port)
	
	// Generate Kyber keypair
	scheme := kyber768.Scheme()
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate Kyber keypair: %v", err)
	}

	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}

	fmt.Printf("📊 Generated Kyber-768 keypair (public: %d bytes, private: %d bytes)\n",
		len(publicKeyBytes), scheme.PrivateKeySize())

	// Start listening
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", port, err)
	}
	defer listener.Close()

	fmt.Printf("🌐 Kyber server listening on port %d...\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		// Handle Kyber key exchange in goroutine
		go m.handleKyberKeyExchange(conn, privateKey, publicKeyBytes)
	}
}

// Handle individual Kyber key exchange
func (m *KyberSockopsManager) handleKyberKeyExchange(conn net.Conn, 
	privateKey kem.PrivateKey, publicKeyBytes []byte) {
	defer conn.Close()

	fmt.Println("🤝 Client connected for Kyber key exchange")

	// Send public key
	message := fmt.Sprintf("%s:%s\n", MSG_PUBLIC_KEY, hex.EncodeToString(publicKeyBytes))
	conn.Write([]byte(message))
	fmt.Println("📤 Sent Kyber public key to client")

	// Receive ciphertext
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Failed to read ciphertext: %v", err)
		return
	}

	response := strings.TrimSpace(string(buffer[:n]))
	if !strings.HasPrefix(response, MSG_CIPHERTEXT+":") {
		log.Printf("Invalid ciphertext message format")
		return
	}

	ciphertextHex := response[len(MSG_CIPHERTEXT)+1:]
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		log.Printf("Failed to decode ciphertext: %v", err)
		return
	}

	// Decapsulate Kyber shared secret
	scheme := kyber768.Scheme()
	sharedSecret, err := scheme.Decapsulate(privateKey, ciphertext)
	if err != nil {
		log.Printf("Failed to decapsulate Kyber secret: %v", err)
		return
	}

	fmt.Printf("🔑 Kyber shared secret established! (%d bytes)\n", len(sharedSecret))
	fmt.Printf("🔑 Secret: %x...\n", sharedSecret[:16])

	// Add crypto state to eBPF for this connection
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	if err := m.AddKyberCryptoState(localAddr.IP, localAddr.Port, sharedSecret); err != nil {
		log.Printf("Failed to add crypto state: %v", err)
		return
	}

	// Test encrypted communication
	n, err = conn.Read(buffer)
	if err != nil {
		log.Printf("Failed to read encrypted data: %v", err)
		return
	}

	encryptedResponse := strings.TrimSpace(string(buffer[:n]))
	if strings.HasPrefix(encryptedResponse, MSG_ENCRYPTED_DATA+":") {
		encryptedHex := encryptedResponse[len(MSG_ENCRYPTED_DATA)+1:]
		encryptedData, err := hex.DecodeString(encryptedHex)
		if err == nil {
			// Decrypt using same method as original
			symmetricKey := sha256.Sum256(sharedSecret)
			decryptedData := xorEncrypt(encryptedData, symmetricKey[:])
			fmt.Printf("🔓 Decrypted message: '%s'\n", string(decryptedData))
		}
	}

	// Send encrypted response
	responseMsg := "Hello from Kyber sockops server!"
	symmetricKey := sha256.Sum256(sharedSecret)
	encryptedResponseData := xorEncrypt([]byte(responseMsg), symmetricKey[:])
	encryptedResponse2 := fmt.Sprintf("%s:%s\n", MSG_ENCRYPTED_DATA, 
		hex.EncodeToString(encryptedResponseData))
	conn.Write([]byte(encryptedResponse2))

	fmt.Println("✅ Kyber key exchange and secure communication complete!")
}

// Helper functions
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func deriveAESKeyFromKyber(kyberSecret []byte) []byte {
	hasher := sha256.New()
	hasher.Write(kyberSecret)
	hasher.Write([]byte("kyber-sockops-aes-key"))
	return hasher.Sum(nil)[:32]
}

func xorEncrypt(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// Get statistics
func (m *KyberSockopsManager) GetStats() (*genpkg.KyberSockopsCryptoStats, error) {
	key := uint32(0)
	var stats genpkg.KyberSockopsCryptoStats
	if err := m.objs.StatsMap.Lookup(&key, &stats); err != nil {
		return nil, err
	}
	return &stats, nil
}

// Print statistics
func (m *KyberSockopsManager) PrintStats() {
	stats, err := m.GetStats()
	if err != nil {
		fmt.Printf("❌ Failed to get stats: %v\n", err)
		return
	}

	fmt.Printf("\n📊 Kyber Sockops Crypto Statistics:\n")
	fmt.Printf("   Messages processed:  %d\n", stats.MessagesProcessed)
	fmt.Printf("   Messages encrypted:  %d\n", stats.MessagesEncrypted)
	fmt.Printf("   Messages decrypted:  %d\n", stats.MessagesDecrypted)
	fmt.Printf("   Encryption errors:   %d\n", stats.EncryptionErrors)
	fmt.Printf("   Active connections:  %d\n", len(m.activeConnections))
}

// Cleanup
func (m *KyberSockopsManager) Cleanup() error {
	// Note: sockMapLink is not available with RawAttachProgram
	// The program will be automatically detached when the map is closed
	if m.cgroupLink != nil {
		m.cgroupLink.Close()
	}
	if m.objs != nil {
		m.objs.Close()
	}
	
	fmt.Printf("✅ Kyber sockops programs detached and cleaned up\n")
	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run kyber_sockops_manager.go <container-name> <mode> [port]")
		fmt.Println("\nModes:")
		fmt.Println("  server [port] - Run Kyber server (default port: 8080)")
		fmt.Println("  client [port] - Run Kyber client (default port: 8080)")
		fmt.Println("\nExample:")
		fmt.Println("  go run kyber_sockops_manager.go my-container server 8080")
		fmt.Println("  go run kyber_sockops_manager.go my-container client 8080")
		return
	}

	containerName := os.Args[1]
	mode := os.Args[2]
	port := 8080

	if len(os.Args) > 3 {
		var err error
		port, err = strconv.Atoi(os.Args[3])
		if err != nil {
			log.Fatalf("Invalid port: %v", err)
		}
	}

	if os.Geteuid() != 0 {
		log.Fatal("❌ This program requires root privileges for eBPF operations")
	}

	// Create Kyber sockops manager
	manager, err := NewKyberSockopsManager(containerName)
	if err != nil {
		log.Fatalf("❌ Failed to create manager: %v", err)
	}

	// Load and attach eBPF programs
	if err := manager.LoadAndAttach(); err != nil {
		log.Fatalf("❌ Failed to load eBPF programs: %v", err)
	}

	// Setup cleanup on exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		<-sigChan
		fmt.Println("\n🛑 Shutting down...")
		manager.PrintStats()
		manager.Cleanup()
		os.Exit(0)
	}()

	// Start statistics printing
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		
		for range ticker.C {
			manager.PrintStats()
		}
	}()

	fmt.Printf("🚀 Kyber sockops system for container: %s\n", containerName)

	switch mode {
	case "server":
		if err := manager.RunKyberServer(port); err != nil {
			log.Fatalf("❌ Server error: %v", err)
		}
	case "client":
		fmt.Printf("🔐 Client mode not implemented yet - use original client\n")
		fmt.Printf("📝 Run your original Kyber client against port %d\n", port)
		// Keep running to maintain eBPF programs
		select {}
	default:
		log.Fatalf("❌ Invalid mode: %s (use 'server' or 'client')", mode)
	}
}