// +build ignore

// Generate a Dilithium5 signature using go-qrllib for cross-verification.
// Outputs: /tmp/goqrllib_dilithium5_pk.bin, /tmp/goqrllib_dilithium5_sig.bin, /tmp/goqrllib_dilithium5_msg.bin
//
// Note: Uses a fixed seed for deterministic cross-verification.

package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/theQRL/go-qrllib/crypto/dilithium"
)

func main() {
	fmt.Println("=== go-qrllib Dilithium5 Signature Generation ===")

	// Fixed test seed (all zeros)
	// go-qrllib will internally hash this with SHAKE256 before key generation
	var seed [dilithium.SEED_BYTES]uint8
	seedHex := "0000000000000000000000000000000000000000000000000000000000000000"
	seedBytes, _ := hex.DecodeString(seedHex)
	copy(seed[:], seedBytes)

	testMessage := "Cross-verification test message for Dilithium5"

	fmt.Printf("Seed: %s\n", seedHex)
	fmt.Printf("Message: %q\n", testMessage)

	// Generate keypair
	dil, err := dilithium.NewDilithiumFromSeed(seed)
	if err != nil {
		fmt.Printf("Failed to create Dilithium: %v\n", err)
		os.Exit(1)
	}

	pk := dil.GetPK()
	fmt.Printf("Public key size: %d bytes\n", len(pk))

	// Sign message
	msg := []byte(testMessage)
	sig, err := dil.Sign(msg)
	if err != nil {
		fmt.Printf("Failed to sign: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Signature size: %d bytes\n", len(sig))
	fmt.Printf("Public key (first 32 bytes): %s\n", hex.EncodeToString(pk[:32]))
	fmt.Printf("Signature (first 32 bytes): %s\n", hex.EncodeToString(sig[:32]))

	// Write output files for qrypto.js to verify
	if err := os.WriteFile("/tmp/goqrllib_dilithium5_pk.bin", pk[:], 0644); err != nil {
		fmt.Printf("Failed to write public key: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile("/tmp/goqrllib_dilithium5_sig.bin", sig[:], 0644); err != nil {
		fmt.Printf("Failed to write signature: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile("/tmp/goqrllib_dilithium5_msg.bin", msg, 0644); err != nil {
		fmt.Printf("Failed to write message: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nOutput files written:")
	fmt.Println("  /tmp/goqrllib_dilithium5_pk.bin")
	fmt.Println("  /tmp/goqrllib_dilithium5_sig.bin")
	fmt.Println("  /tmp/goqrllib_dilithium5_msg.bin")
	fmt.Println("\n✓ go-qrllib signature generation complete")
}
