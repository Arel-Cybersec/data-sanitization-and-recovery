/* crypto_windows.c - crypto primitives via Windows CNG (bcrypt.dll).
 * SPDX-License-Identifier: MIT
 *
 * Uses only the OS-provided, FIPS-validated CNG provider: no extra DLLs.
 * AES-CTR is built from AES-ECB over big-endian counter blocks (the standard
 * construction, NIST SP 800-38A section 6.5). */
#include "erasecure.h"

#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>

#define OK(s) BCRYPT_SUCCESS(s)

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
    return OK(BCryptGenRandom(NULL, buf, (ULONG)n,
                              BCRYPT_USE_SYSTEM_PREFERRED_RNG)) ? 0 : -1;
}

struct ec_sha { BCRYPT_ALG_HANDLE alg; BCRYPT_HASH_HANDLE h; };

ec_sha *ec_sha_new(void)
{
    ec_sha *s = calloc(1, sizeof *s);
    if (s && OK(BCryptOpenAlgorithmProvider(&s->alg, BCRYPT_SHA256_ALGORITHM, NULL, 0)) &&
        OK(BCryptCreateHash(s->alg, &s->h, NULL, 0, NULL, 0, 0)))
        return s;
    if (s && s->alg) BCryptCloseAlgorithmProvider(s->alg, 0);
    free(s);
    return NULL;
}

int ec_sha_update(ec_sha *s, const void *d, size_t n)
{
    return OK(BCryptHashData(s->h, (PUCHAR)d, (ULONG)n, 0)) ? 0 : -1;
}

int ec_sha_final(ec_sha *s, char out[65])
{
    unsigned char md[32];
    int rc = OK(BCryptFinishHash(s->h, md, 32, 0)) ? 0 : -1;
    hex(md, out);
    BCryptDestroyHash(s->h);
    BCryptCloseAlgorithmProvider(s->alg, 0);
    free(s);
    return rc;
}

int ec_sha256_hex(const void *d, size_t n, char out[65])
{
    ec_sha *s = ec_sha_new();
    if (!s) return -1;
    ec_sha_update(s, d, n);
    return ec_sha_final(s, out);
}

struct ec_ctr {
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_KEY_HANDLE key;
    unsigned char ctr[16];
};

ec_ctr *ec_ctr_new(const unsigned char key[32])
{
    ec_ctr *c = calloc(1, sizeof *c);
    if (c && OK(BCryptOpenAlgorithmProvider(&c->alg, BCRYPT_AES_ALGORITHM, NULL, 0)) &&
        OK(BCryptSetProperty(c->alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                             sizeof BCRYPT_CHAIN_MODE_ECB, 0)) &&
        OK(BCryptGenerateSymmetricKey(c->alg, &c->key, NULL, 0, (PUCHAR)key, 32, 0)))
        return c;
    ec_ctr_free(c);
    return NULL;
}

static void put_counters(ec_ctr *c, unsigned char *buf, size_t blocks)
{
    for (size_t b = 0; b < blocks; b++) {
        memcpy(buf + 16 * b, c->ctr, 16);
        for (int i = 15; i >= 0 && ++c->ctr[i] == 0; i--)
            ;
    }
}

int ec_ctr_stream(ec_ctr *c, unsigned char *buf, size_t n)
{
    ULONG got;
    size_t full = n / 16, tail = n % 16;
    put_counters(c, buf, full);
    if (full && !OK(BCryptEncrypt(c->key, buf, (ULONG)(full * 16), NULL, NULL, 0,
                                  buf, (ULONG)(full * 16), &got, 0)))
        return -1;
    if (tail) {
        unsigned char ks[16];
        put_counters(c, ks, 1);
        if (!OK(BCryptEncrypt(c->key, ks, 16, NULL, NULL, 0, ks, 16, &got, 0)))
            return -1;
        memcpy(buf + full * 16, ks, tail);
    }
    return 0;
}

void ec_ctr_free(ec_ctr *c)
{
    if (!c) return;
    if (c->key) BCryptDestroyKey(c->key);
    if (c->alg) BCryptCloseAlgorithmProvider(c->alg, 0);
    SecureZeroMemory(c, sizeof *c);
    free(c);
}
