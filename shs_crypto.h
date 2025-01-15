#ifndef SHS_CRYPTO_H
#define SHS_CRYPTO_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

void sha1(const uint8_t *message, size_t length, uint8_t hash[20]);

void sha256(const uint8_t *message, size_t length, uint8_t hash[32]);

#endif