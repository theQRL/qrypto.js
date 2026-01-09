// +build ignore

// Generate an ML-DSA-87 signature using go-qrllib for cross-verification.
// Outputs: /tmp/goqrllib_mldsa87_pk.bin, /tmp/goqrllib_mldsa87_sig.bin, /tmp/goqrllib_mldsa87_msg.bin, /tmp/goqrllib_mldsa87_ctx.bin
//
// Note: Uses a fixed seed for deterministic cross-verification.
// ML-DSA-87 does NOT pre-hash the seed (unlike Dilithium5).

package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
)

func main() {
	fmt.Println("=== go-qrllib ML-DSA-87 Signature Generation ===")

	// Fixed test seed (all zeros)
	var seed [ml_dsa_87.SEED_BYTES]uint8
	seedHex := "0000000000000000000000000000000000000000000000000000000000000000"
	seedBytes, _ := hex.DecodeString(seedHex)
	copy(seed[:], seedBytes)

	testMessage := "Cross-verification test message for ML-DSA-87"
	context := []byte("ZOND") // Standard context used by QRL

	fmt.Printf("Seed: %s\n", seedHex)
	fmt.Printf("Message: %q\n", testMessage)
	fmt.Printf("Context: %q\n", string(context))

	// Generate keypair
	mldsa, err := ml_dsa_87.NewMLDSA87FromSeed(seed)
	if err != nil {
		fmt.Printf("Failed to create ML-DSA-87: %v\n", err)
		os.Exit(1)
	}

	pk := mldsa.GetPK()
	fmt.Printf("Public key size: %d bytes\n", len(pk))

	// Sign message with context
	msg := []byte(testMessage)
	sig, err := mldsa.Sign(context, msg)
	if err != nil {
		fmt.Printf("Failed to sign: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Signature size: %d bytes\n", len(sig))
	fmt.Printf("Public key (first 32 bytes): %s\n", hex.EncodeToString(pk[:32]))
	fmt.Printf("Signature (first 32 bytes): %s\n", hex.EncodeToString(sig[:32]))

	// Write output files for qrypto.js to verify
	if err := os.WriteFile("/tmp/goqrllib_mldsa87_pk.bin", pk[:], 0644); err != nil {
		fmt.Printf("Failed to write public key: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile("/tmp/goqrllib_mldsa87_sig.bin", sig[:], 0644); err != nil {
		fmt.Printf("Failed to write signature: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile("/tmp/goqrllib_mldsa87_msg.bin", msg, 0644); err != nil {
		fmt.Printf("Failed to write message: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile("/tmp/goqrllib_mldsa87_ctx.bin", context, 0644); err != nil {
		fmt.Printf("Failed to write context: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nOutput files written:")
	fmt.Println("  /tmp/goqrllib_mldsa87_pk.bin")
	fmt.Println("  /tmp/goqrllib_mldsa87_sig.bin")
	fmt.Println("  /tmp/goqrllib_mldsa87_msg.bin")
	fmt.Println("  /tmp/goqrllib_mldsa87_ctx.bin")
	fmt.Println("\n✓ go-qrllib signature generation complete")
}
