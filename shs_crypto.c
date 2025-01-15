/*****************************************************
 * Author: Matheo ENEE
 * Date: 15.01.2025
 * 
 * Description:
 * This file implements the  Secure Hash Standard (SHS)
 * as specified in FIPS PUB 180-4. It provides functions for 
 * hashing in compliance with the standard requirements.
 * 
 * Compliance:
 * - This implementation follows the Federal Information 
 *   Processing Standards Publication 180-4 (FIPS PUB 180-4).
 * 
 *****************************************************/

#include "shs_crypto.h"
#include "shs_functions.h"

void sha1(const char *file_path, uint8_t hash[20]) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("File opening failed");
        return;
    }

    size_t bytes_read;

    uint64_t total_bits = 0;
    uint32_t H[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

    // Seek to the end of the file to determine its size
    fseek(file, 0, SEEK_END);
    total_bits = ftell(file) * 8;  // Convert size from bytes to bits
    fseek(file, 0, SEEK_SET);  // Return to the start of the file

    // Padding and appending length (this is done after processing the file)
    size_t padded_len = ((total_bits + 72) / 512 + 1) * 64;

    uint8_t padded[padded_len];
    memset(padded, 0, padded_len);
    
    // Copy content to padded
    fseek(file, 0, SEEK_SET);
    size_t idx = 0;
    while ((bytes_read = fread(padded + idx, 1, BLOCK_SIZE, file)) > 0) {
        idx += bytes_read;
    }
    
    // Add padding
    padded[idx] = 0x80;
    memset(padded + idx + 1, 0, padded_len - idx - 9);

    // Append length in bits
    for (int i = 0; i < 8; ++i) {
        padded[padded_len - 1 - i] = (total_bits >> (i * 8)) & 0xFF;
    }

    // Process the padded data
    for (size_t i = 0; i < padded_len; i += BLOCK_SIZE) {
        sha1_process_block(padded + i, H);
    }

    // Convert the result to the hash (big-endian)
    for (int i = 0; i < 5; ++i) {
        hash[i * 4] = (H[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (H[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (H[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = H[i] & 0xFF;
    }

    fclose(file);
}

void sha256(const char *file_path, uint8_t hash[32]) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("File opening failed");
        return;
    }

    size_t bytes_read;

    uint64_t total_bits = 0;
    uint32_t H[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    // Seek to the end of the file to determine its size
    fseek(file, 0, SEEK_END);
    total_bits = ftell(file) * 8;  // Convert size from bytes to bits
    fseek(file, 0, SEEK_SET);  // Return to the start of the file

    // Padding and appending length (this is done after processing the file)
    size_t padded_len = ((total_bits + 72) / 512 + 1) * 64;
    uint8_t padded[padded_len];
    memset(padded, 0, padded_len);
    
    // Copy content to padded
    fseek(file, 0, SEEK_SET);
    size_t idx = 0;
    while ((bytes_read = fread(padded + idx, 1, BLOCK_SIZE, file)) > 0) {
        idx += bytes_read;
    }

    // Add padding
    padded[idx] = 0x80;
    memset(padded + idx + 1, 0, padded_len - idx - 9);

    // Append length in bits
    for (int i = 0; i < 8; ++i) {
        padded[padded_len - 1 - i] = (total_bits >> (i * 8)) & 0xFF;
    }

    // Process the padded data (final block)
    for (size_t i = 0; i < padded_len; i += BLOCK_SIZE) {
        sha256_process_block(padded + i, H);
    }

    // Convert the result to the hash (big-endian)
    for (int i = 0; i < 8; ++i) {
        hash[i * 4] = (H[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (H[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (H[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = H[i] & 0xFF;
    }

    fclose(file);
}