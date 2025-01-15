#include "shs_crypto.h"

int main() {
    const char *file_path = "frog.jpeg";  // Provide the path to the file
    uint8_t sha256_hash[32];
    uint8_t sha1_hash[20];

    // Calculate the hashes for the file
    sha1(file_path, sha1_hash);
    sha256(file_path, sha256_hash);

    // Print the SHA-256 hash
    printf("SHA-256 hash: ");
    for (int i = 0; i < 32; ++i) {
        printf("%02x", sha256_hash[i]);
    }
    printf("\n");

    // Print the SHA-1 hash
    printf("SHA-1 hash: ");
    for (int i = 0; i < 20; ++i) {
        printf("%02x", sha1_hash[i]);
    }
    printf("\n");

    return 0;
}