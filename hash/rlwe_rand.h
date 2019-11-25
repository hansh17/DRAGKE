#ifndef _RAND_H_
#define _RAND_H_

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>


/* Returns 1 on success, 0 on failure. */
int openssl_aes_init(EVP_CIPHER_CTX *rand_ctx);
void openssl_aes_cleanup(EVP_CIPHER_CTX *rand_ctx);

uint8_t  RANDOM8 (EVP_CIPHER_CTX *rand_ctx);
uint32_t RANDOM32(EVP_CIPHER_CTX *rand_ctx);
uint64_t RANDOM64(EVP_CIPHER_CTX *rand_ctx);
void RANDOM192(uint64_t r[3], EVP_CIPHER_CTX *rand_ctx);

extern void *(*volatile rlwe_memset_volatile)(void *, int, size_t);

#endif
