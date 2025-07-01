// main.go
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// Message types for our protocol
const (
	MSG_PUBLIC_KEY = "PUBLIC_KEY"
	MSG_CIPHERTEXT = "CIPHERTEXT" 
	MSG_ENCRYPTED_DATA = "ENCRYPTED_DATA"
)

// Simple XOR encryption for demonstration
func xorEncrypt(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// Server function - acts as the key holder
func runServer() {
	fmt.Println("🔐 SERVER: Starting Kyber KEM server...")
	
	// Step 1: Generate Kyber key pair
	fmt.Println("📊 SERVER: Generating Kyber-768 key pair...")
	
	// Get the KEM scheme
	scheme := kyber768.Scheme()
	
	// Generate key pair
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		log.Fatal("Failed to generate key pair:", err)
	}
	
	// Convert keys to byte slices for transmission
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		log.Fatal("Failed to marshal public key:", err)
	}
	
	fmt.Printf("✅ SERVER: Generated keys - Public key size: %d bytes, Private key size: %d bytes\n", 
		len(publicKeyBytes), scheme.PrivateKeySize())

	// Start listening
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal("Failed to listen:", err)
	}
	defer listener.Close()
	
	fmt.Println("🌐 SERVER: Listening on :8080...")

	conn, err := listener.Accept()
	if err != nil {
		log.Fatal("Failed to accept connection:", err)
	}
	defer conn.Close()
	
	fmt.Println("🤝 SERVER: Client connected!")

	// Step 2: Send public key to client
	fmt.Println("📤 SERVER: Sending public key to client...")
	message := fmt.Sprintf("%s:%s", MSG_PUBLIC_KEY, hex.EncodeToString(publicKeyBytes))
	conn.Write([]byte(message + "\n"))

	// Step 3: Receive ciphertext from client
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Fatal("Failed to read from client:", err)
	}
	
	response := strings.TrimSpace(string(buffer[:n]))
	fmt.Println("📥 SERVER: Received ciphertext from client")
	
	// Parse the ciphertext
	if len(response) < len(MSG_CIPHERTEXT)+1 {
		log.Fatal("Invalid message format")
	}
	
	ciphertextHex := response[len(MSG_CIPHERTEXT)+1:]
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		log.Fatal("Failed to decode ciphertext:", err)
	}

	// Step 4: Decapsulate to get shared secret
	fmt.Println("🔓 SERVER: Decapsulating shared secret...")
	sharedSecret, err := scheme.Decapsulate(privateKey, ciphertext)
	if err != nil {
		log.Fatal("Failed to decapsulate:", err)
	}
	
	// Hash the shared secret to get a symmetric key
	hash := sha256.Sum256(sharedSecret)
	symmetricKey := hash[:]
	
	fmt.Printf("🔑 SERVER: Shared secret established! (32 bytes)\n")
	fmt.Printf("🔑 SERVER: Symmetric key: %s...\n", hex.EncodeToString(symmetricKey)[:16])

	// Step 5: Wait for encrypted data from client
	n, err = conn.Read(buffer)
	if err != nil {
		log.Fatal("Failed to read encrypted data:", err)
	}
	
	encryptedResponse := strings.TrimSpace(string(buffer[:n]))
	fmt.Println("📥 SERVER: Received encrypted message from client")
	
	// Parse encrypted data
	if len(encryptedResponse) < len(MSG_ENCRYPTED_DATA)+1 {
		log.Fatal("Invalid encrypted message format")
	}
	
	encryptedHex := encryptedResponse[len(MSG_ENCRYPTED_DATA)+1:]
	encryptedData, err := hex.DecodeString(encryptedHex)
	if err != nil {
		log.Fatal("Failed to decode encrypted data:", err)
	}

	// Decrypt the message
	decryptedData := xorEncrypt(encryptedData, symmetricKey)
	fmt.Printf("🔓 SERVER: Decrypted message: '%s'\n", string(decryptedData))
	
	// Send encrypted response back
	responseMsg := "Hello from server! Kyber key exchange successful!"
	encryptedResponse2 := xorEncrypt([]byte(responseMsg), symmetricKey)
	conn.Write([]byte(fmt.Sprintf("%s:%s\n", MSG_ENCRYPTED_DATA, hex.EncodeToString(encryptedResponse2))))
	
	fmt.Println("✅ SERVER: Sent encrypted response to client")
	fmt.Println("🎉 SERVER: Key exchange and secure communication complete!")
}

// Client function - initiates the key exchange
func runClient() {
	// Give server time to start
	time.Sleep(2 * time.Second)
	
	fmt.Println("🔐 CLIENT: Connecting to Kyber KEM server...")
	
	conn, err := net.Dial("tcp", ":8080")
	if err != nil {
		log.Fatal("Failed to connect to server:", err)
	}
	defer conn.Close()
	
	fmt.Println("🤝 CLIENT: Connected to server!")

	// Get the KEM scheme
	scheme := kyber768.Scheme()

	// Step 1: Receive public key from server
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Fatal("Failed to read from server:", err)
	}
	
	response := strings.TrimSpace(string(buffer[:n]))
	fmt.Println("📥 CLIENT: Received public key from server")
	
	// Parse the public key
	if len(response) < len(MSG_PUBLIC_KEY)+1 {
		log.Fatal("Invalid message format")
	}
	
	publicKeyHex := response[len(MSG_PUBLIC_KEY)+1:]
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		log.Fatal("Failed to decode public key:", err)
	}

	// Unmarshal the public key
	publicKey, err := scheme.UnmarshalBinaryPublicKey(publicKeyBytes)
	if err != nil {
		log.Fatal("Failed to unmarshal public key:", err)
	}

	fmt.Printf("📊 CLIENT: Received public key (%d bytes)\n", len(publicKeyBytes))

	// Step 2: Encapsulate shared secret using server's public key
	fmt.Println("🔒 CLIENT: Encapsulating shared secret...")
	ciphertext, sharedSecret, err := scheme.Encapsulate(publicKey)
	if err != nil {
		log.Fatal("Failed to encapsulate:", err)
	}
	
	// Hash the shared secret to get a symmetric key
	hash := sha256.Sum256(sharedSecret)
	symmetricKey := hash[:]
	
	fmt.Printf("🔑 CLIENT: Shared secret established! (32 bytes)\n")
	fmt.Printf("🔑 CLIENT: Symmetric key: %s...\n", hex.EncodeToString(symmetricKey)[:16])

	// Step 3: Send ciphertext to server
	message := fmt.Sprintf("%s:%s", MSG_CIPHERTEXT, hex.EncodeToString(ciphertext))
	conn.Write([]byte(message + "\n"))
	fmt.Println("📤 CLIENT: Sent ciphertext to server")

	// Step 4: Send encrypted message to server
	secretMessage := "Hello from client! This is encrypted with our shared Kyber secret!"
	encryptedMessage := xorEncrypt([]byte(secretMessage), symmetricKey)
	
	encryptedMsg := fmt.Sprintf("%s:%s", MSG_ENCRYPTED_DATA, hex.EncodeToString(encryptedMessage))
	conn.Write([]byte(encryptedMsg + "\n"))
	fmt.Printf("🔒 CLIENT: Sent encrypted message: '%s'\n", secretMessage)

	// Step 5: Receive encrypted response from server
	n, err = conn.Read(buffer)
	if err != nil {
		log.Fatal("Failed to read server response:", err)
	}
	
	serverResponse := strings.TrimSpace(string(buffer[:n]))
	fmt.Println("📥 CLIENT: Received encrypted response from server")
	
	// Parse and decrypt server response
	if len(serverResponse) < len(MSG_ENCRYPTED_DATA)+1 {
		log.Fatal("Invalid server response format")
	}
	
	encryptedHex := serverResponse[len(MSG_ENCRYPTED_DATA)+1:]
	encryptedData, err := hex.DecodeString(encryptedHex)
	if err != nil {
		log.Fatal("Failed to decode server response:", err)
	}

	decryptedResponse := xorEncrypt(encryptedData, symmetricKey)
	fmt.Printf("🔓 CLIENT: Decrypted server response: '%s'\n", string(decryptedResponse))
	
	fmt.Println("🎉 CLIENT: Key exchange and secure communication complete!")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go [server|client]")
		return
	}
	
	switch os.Args[1] {
	case "server":
		runServer()
	case "client":
		runClient()
	default:
		fmt.Println("Invalid argument. Use 'server' or 'client'")
	}
}