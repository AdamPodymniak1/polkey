#pragma once
#include "md.h"
int mbedtls_pkcs5_pbkdf2_hmac_ext(mbedtls_md_type_t type, const unsigned char *pw, size_t plen, const unsigned char *salt, size_t slen, unsigned int iters, uint32_t keylen, unsigned char *out);
