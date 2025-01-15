#include "shs_functions.h"

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define SHR(x, n) ((x) >> (n))

/****************
*     SHA-1
****************/

// SHA-1 constants
const uint32_t SHA1_K[4] = {
    0x5A827999, // 0 <= t <= 19
    0x6ED9EBA1, // 20 <= t <= 39
    0x8F1BBCDC, // 40 <= t <= 59
    0xCA62C1D6  // 60 <= t <= 79
};

void sha1_process_block(const uint8_t *block, uint32_t *H) {
    uint32_t W[80];
    uint32_t a, b, c, d, e, f, temp;

    // Prepare the message schedule
    for (int t = 0; t < 16; ++t) {
        W[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) |
               (block[t * 4 + 2] << 8) | (block[t * 4 + 3]);
    }
    for (int t = 16; t < 80; ++t) {
        W[t] = ROTL(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    // Initialize working variables
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];

    // Main loop
    for (int t = 0; t < 80; ++t) {
        if (t < 20)
            f = (b & c) | ((~b) & d);
        else if (t < 40)
            f = b ^ c ^ d;
        else if (t < 60)
            f = (b & c) | (b & d) | (c & d);
        else
            f = b ^ c ^ d;

        temp = ROTL(a, 5) + f + e + SHA1_K[t / 20] + W[t];
        e = d;
        d = c;
        c = ROTL(b, 30);
        b = a;
        a = temp;
    }

    // Compute intermediate hash values
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
}

/****************
*    SHA-256
****************/

const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t Sigma0(uint32_t x) {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

uint32_t Sigma1(uint32_t x) {
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

uint32_t sigma0(uint32_t x) {
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
}

uint32_t sigma1(uint32_t x) {
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
}

void sha256_process_block(const uint8_t *block, uint32_t *H) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h, T1, T2;

    // Prepare the message schedule
    for (int t = 0; t < 16; ++t) {
        W[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) |
               (block[t * 4 + 2] << 8) | (block[t * 4 + 3]);
    }
    for (int t = 16; t < 64; ++t) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }

    // Initialize working variables
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    // Main loop
    for (int t = 0; t < 64; ++t) {
        T1 = h + Sigma1(e) + Ch(e, f, g) + SHA256_K[t] + W[t];
        T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // Compute intermediate hash values
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}

