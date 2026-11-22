#pragma once
#include <stdint.h>
#include <stddef.h>
typedef enum { MBEDTLS_MD_NONE = 0, MBEDTLS_MD_SHA256 = 6 } mbedtls_md_type_t;
typedef struct mbedtls_md_info_t { int type; } mbedtls_md_info_t;
typedef struct mbedtls_md_context_t {
    void *state;
    int hmac;
} mbedtls_md_context_t;
const mbedtls_md_info_t *mbedtls_md_info_from_type(mbedtls_md_type_t t);
void mbedtls_md_init(mbedtls_md_context_t *c);
void mbedtls_md_free(mbedtls_md_context_t *c);
int mbedtls_md_setup(mbedtls_md_context_t *c, const mbedtls_md_info_t *i, int hmac);
int mbedtls_md_starts(mbedtls_md_context_t *c);
int mbedtls_md_update(mbedtls_md_context_t *c, const unsigned char *in, size_t n);
int mbedtls_md_finish(mbedtls_md_context_t *c, unsigned char *out);
int mbedtls_md_hmac_starts(mbedtls_md_context_t *c, const unsigned char *key, size_t n);
int mbedtls_md_hmac_update(mbedtls_md_context_t *c, const unsigned char *in, size_t n);
int mbedtls_md_hmac_finish(mbedtls_md_context_t *c, unsigned char *out);
