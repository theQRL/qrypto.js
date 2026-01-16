// +build ignore

// Generate a Dilithium5 signature using go-qrllib for cross-verification.
// Outputs: $TMPDIR/qrypto_cross_verify/goqrllib_dilithium5_{pk,sig,msg}.bin
//
// Note: Uses a fixed seed for deterministic cross-verification.

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

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

	// Create secure output directory (remove any existing symlink/file first)
	outputDir := filepath.Join(os.TempDir(), "qrypto_cross_verify")
	if err := os.RemoveAll(outputDir); err != nil {
		fmt.Printf("Failed to clean output directory: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		fmt.Printf("Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	// Write output files for qrypto.js to verify
	pkPath := filepath.Join(outputDir, "goqrllib_dilithium5_pk.bin")
	sigPath := filepath.Join(outputDir, "goqrllib_dilithium5_sig.bin")
	msgPath := filepath.Join(outputDir, "goqrllib_dilithium5_msg.bin")

	if err := os.WriteFile(pkPath, pk[:], 0600); err != nil {
		fmt.Printf("Failed to write public key: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(sigPath, sig[:], 0600); err != nil {
		fmt.Printf("Failed to write signature: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(msgPath, msg, 0600); err != nil {
		fmt.Printf("Failed to write message: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nOutput files written:")
	fmt.Printf("  %s\n", pkPath)
	fmt.Printf("  %s\n", sigPath)
	fmt.Printf("  %s\n", msgPath)
	fmt.Println("\n✓ go-qrllib signature generation complete")
}
