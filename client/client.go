package main

import (
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem"
)

func main() {
	// Connect to server
	conn, err := net.Dial("tcp", "localhost:9000")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// Receive public key
	var pubKey kem.PublicKey
	dec := gob.NewDecoder(conn)
	if err := dec.Decode(&pubKey); err != nil {
		log.Fatal(err)
	}
	fmt.Println("📥 Received public key from server")

	// Encapsulate to get ciphertext and shared secret
	ct, ss, err := pubKey.Scheme().Encapsulate(pubKey)
	if err != nil {
		log.Fatal(err)
	}

	// Send ciphertext to server
	enc := gob.NewEncoder(conn)
	if err := enc.Encode(ct); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("📤 Sent ciphertext to server: %x\n", ct)
	fmt.Printf("🧠 Client's shared secret: %x\n", ss)
}
