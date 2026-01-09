/*
 * dilithium5_sign_ref.c - Generate Dilithium5 signature with pq-crystals reference
 * Compile: gcc -DDILITHIUM_MODE=5 -I. -O2
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "params.h"
#include "sign.h"

int main() {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];
    size_t siglen;
    FILE *f;

    printf("=== pq-crystals Dilithium5 Signature Generation ===\n");

    /* Generate random keypair */
    crypto_sign_keypair(pk, sk);

    uint8_t msg[] = "Cross-verification test message from pq-crystals Dilithium5";
    size_t msglen = strlen((char*)msg);

    /* Sign message */
    crypto_sign_signature(sig, &siglen, msg, msglen, sk);

    /* Self-verify */
    int ret = crypto_sign_verify(sig, siglen, msg, msglen, pk);
    if (ret != 0) {
        printf("Self-verification failed!\n");
        return 1;
    }

    printf("PK size:  %d bytes\n", CRYPTO_PUBLICKEYBYTES);
    printf("SK size:  %d bytes\n", CRYPTO_SECRETKEYBYTES);
    printf("Sig size: %zu bytes\n", siglen);
    printf("Message:  \"%s\"\n", msg);
    printf("Self-verify: PASSED\n");

    /* Write output files */
    f = fopen("/tmp/ref_dilithium5_pk.bin", "wb");
    fwrite(pk, 1, CRYPTO_PUBLICKEYBYTES, f);
    fclose(f);

    f = fopen("/tmp/ref_dilithium5_sig.bin", "wb");
    fwrite(sig, 1, siglen, f);
    fclose(f);

    f = fopen("/tmp/ref_dilithium5_msg.bin", "wb");
    fwrite(msg, 1, msglen, f);
    fclose(f);

    printf("\nOutput files written:\n");
    printf("  /tmp/ref_dilithium5_pk.bin\n");
    printf("  /tmp/ref_dilithium5_sig.bin\n");
    printf("  /tmp/ref_dilithium5_msg.bin\n");
    printf("\n✓ pq-crystals signature generation complete\n");

    return 0;
}
