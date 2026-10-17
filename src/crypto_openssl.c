/* crypto_openssl.c - crypto primitives via OpenSSL (Linux).
 * SPDX-License-Identifier: MIT */
#include "erasecure.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>

static void hex(const unsigned char md[32], char out[65])
{
    static const char d[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i] = d[md[i] >> 4];
        out[2 * i + 1] = d[md[i] & 15];
    }
    out[64] = 0;
}

int ec_random(void *buf, size_t n)
{
    return RAND_bytes(buf, (int)n) == 1 ? 0 : -1;
}

struct ec_sha { EVP_MD_CTX *c; };

ec_sha *ec_sha_new(void)
{
    ec_sha *h = malloc(sizeof *h);
    if (h && (h->c = EVP_MD_CTX_new()) &&
        EVP_DigestInit_ex(h->c, EVP_sha256(), NULL) == 1)
        return h;
    if (h) EVP_MD_CTX_free(h->c);
    free(h);
    return NULL;
}

int ec_sha_update(ec_sha *h, const void *d, size_t n)
{
    return EVP_DigestUpdate(h->c, d, n) == 1 ? 0 : -1;
}

int ec_sha_final(ec_sha *h, char out[65])
{
    unsigned char md[32];
    int rc = EVP_DigestFinal_ex(h->c, md, NULL) == 1 ? 0 : -1;
    hex(md, out);
    EVP_MD_CTX_free(h->c);
    free(h);
    return rc;
}

int ec_sha256_hex(const void *d, size_t n, char out[65])
{
    ec_sha *h = ec_sha_new();
    if (!h) return -1;
    ec_sha_update(h, d, n);
    return ec_sha_final(h, out);
}

struct ec_ctr { EVP_CIPHER_CTX *c; };

ec_ctr *ec_ctr_new(const unsigned char key[32])
{
    static const unsigned char iv[16] = {0};
    ec_ctr *c = malloc(sizeof *c);
    if (c && (c->c = EVP_CIPHER_CTX_new()) &&
        EVP_EncryptInit_ex(c->c, EVP_aes_256_ctr(), NULL, key, iv) == 1)
        return c;
    if (c) EVP_CIPHER_CTX_free(c->c);
    free(c);
    return NULL;
}

int ec_ctr_stream(ec_ctr *c, unsigned char *buf, size_t n)
{
    int out = 0;
    for (size_t i = 0; i < n; i++) buf[i] = 0;
    return EVP_EncryptUpdate(c->c, buf, &out, buf, (int)n) == 1 &&
           (size_t)out == n ? 0 : -1;
}

void ec_ctr_free(ec_ctr *c)
{
    if (!c) return;
    EVP_CIPHER_CTX_free(c->c);
    free(c);
}
