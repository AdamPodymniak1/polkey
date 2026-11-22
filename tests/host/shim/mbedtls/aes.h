#pragma once
#include <stdint.h>
#include <stddef.h>
#define MBEDTLS_AES_ENCRYPT 1
#define MBEDTLS_AES_DECRYPT 0
typedef struct mbedtls_aes_context {
    unsigned char key[32];
    int enc;
} mbedtls_aes_context;
void mbedtls_aes_init(mbedtls_aes_context *c);
void mbedtls_aes_free(mbedtls_aes_context *c);
int mbedtls_aes_setkey_enc(mbedtls_aes_context *c, const unsigned char *key, unsigned bits);
int mbedtls_aes_setkey_dec(mbedtls_aes_context *c, const unsigned char *key, unsigned bits);
int mbedtls_aes_crypt_cbc(mbedtls_aes_context *c, int mode, size_t len, unsigned char iv[16], const unsigned char *in, unsigned char *out);
