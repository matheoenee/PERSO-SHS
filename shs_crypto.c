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

void sha1(const uint8_t *message, size_t length, uint8_t hash[20]) {
    uint64_t bit_len = length * 8;
    size_t padded_len = ((length + 9) / BLOCK_SIZE + 1) * BLOCK_SIZE;
    uint8_t padded[padded_len];

    // Copy message into padded buffer
    memcpy(padded, message, length);

    // Add padding
    padded[length] = 0x80;
    memset(padded + length + 1, 0, padded_len - length - 9);

    // Append original message length in bits
    for (int i = 0; i < 8; ++i) {
        padded[padded_len - 1 - i] = (bit_len >> (i * 8)) & 0xFF;
    }

    // Setting initial hash values 
    uint32_t H[5] = {
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0
    };

    // Process each 512-bit block
    for (size_t i = 0; i < padded_len; i += BLOCK_SIZE) {
        sha1_process_block(padded + i, H);
    }

    // Produce the final hash value (big-endian)
    for (int i = 0; i < 5; ++i) {
        hash[i * 4] = (H[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (H[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (H[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = H[i] & 0xFF;
    }
}

void sha256(const uint8_t *message, size_t length, uint8_t hash[32]) {
    uint64_t bit_len = length * 8;
    size_t padded_len = ((length + 9) / BLOCK_SIZE + 1) * BLOCK_SIZE;
    uint8_t padded[padded_len];

    // Copy message into padded buffer
    memcpy(padded, message, length);

    // Add padding
    padded[length] = 0x80;
    memset(padded + length + 1, 0, padded_len - length - 9);

    // Append original message length in bits
    for (int i = 0; i < 8; ++i) {
        padded[padded_len - 1 - i] = (bit_len >> (i * 8)) & 0xFF;
    }

    // Setting initial hash values
    uint32_t H[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };

    // Process each 512-bit block
    for (size_t i = 0; i < padded_len; i += BLOCK_SIZE) {
        sha256_process_block(padded + i, H);
    }

    // Produce the final hash value (big-endian)
    for (int i = 0; i < 8; ++i) {
        hash[i * 4] = (H[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (H[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (H[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = H[i] & 0xFF;
    }
}

