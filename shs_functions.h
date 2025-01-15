#ifndef SHS_FUNCTIONS_H
#define SHS_FUNCTIONS_H

#define BLOCK_SIZE 64

#include <stdint.h>

void sha1_process_block(const uint8_t *block, uint32_t *H);

uint32_t Ch(uint32_t x, uint32_t y, uint32_t z);

uint32_t Maj(uint32_t x, uint32_t y, uint32_t z);

uint32_t Sigma0(uint32_t x);

uint32_t Sigma1(uint32_t x);

uint32_t sigma0(uint32_t x);

uint32_t sigma1(uint32_t x);

void sha256_process_block(const uint8_t *block, uint32_t *H);

#endif