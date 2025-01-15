#include "shs_crypto.h"

int main() {
    const char *message = "abc";
    uint8_t sha256_hash[32];
    uint8_t sha1_hash[20];

    sha1((const uint8_t *)message, strlen(message), sha1_hash);
    sha256((const uint8_t *)message, strlen(message), sha256_hash);

    printf("SHA-256 hash: ");
    for (int i = 0; i < 32; ++i) {
        printf("%02x", sha256_hash[i]);
    }
    printf("\n");

    printf("SHA-1 hash: ");
    for (int i = 0; i < 20; ++i) {
        printf("%02x", sha1_hash[i]);
    }
    printf("\n");

    return 0;
}