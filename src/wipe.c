/* wipe.c - single/multi-pass overwrite with read-back verification.
 * SPDX-License-Identifier: MIT
 *
 * Random data is an AES-256-CTR keystream under a fresh random key per pass.
 * It is fast, unpredictable to anyone without the key, and reproducible, so
 * verification regenerates the exact stream and compares every byte. */
#include "erasecure.h"

#include <stdlib.h>
#include <string.h>

#define CHUNK (1u << 20) /* 1 MiB: a multiple of every real sector size */

void *ec_alloc_aligned(size_t n, void **raw)
{
    *raw = malloc(n + 4096);
    return *raw ? (void *)(((uintptr_t)*raw + 4095) & ~(uintptr_t)4095) : NULL;
}

static int fill(ec_ctr *c, unsigned char *buf, size_t n)
{
    if (!c) {
        memset(buf, 0, n);
        return 0;
    }
    return ec_ctr_stream(c, buf, n);
}

int ec_overwrite(ec_target *t, uint64_t size, enum ec_pattern pat, int verify,
                 char err[EC_ERRLEN])
{
    void *rb, *rc2;
    unsigned char key[32], *buf = ec_alloc_aligned(CHUNK, &rb),
                           *chk = ec_alloc_aligned(CHUNK, &rc2);
    ec_ctr *c = NULL;
    int rc = -1;
    if (!buf || !chk) {
        snprintf(err, EC_ERRLEN, "out of memory");
        goto out;
    }
    if (pat == EC_RANDOM && (ec_random(key, sizeof key) || !(c = ec_ctr_new(key)))) {
        snprintf(err, EC_ERRLEN, "random generator failed");
        goto out;
    }
    for (uint64_t off = 0; off < size; off += CHUNK) {
        size_t n = size - off < CHUNK ? (size_t)(size - off) : CHUNK;
        if (fill(c, buf, n) || ec_os_pwrite(t, buf, n, off)) {
            snprintf(err, EC_ERRLEN, "write failed at offset %llu",
                     (unsigned long long)off);
            goto out;
        }
    }
    if (ec_os_sync(t)) {
        snprintf(err, EC_ERRLEN, "flush to disk failed");
        goto out;
    }
    if (verify) {
        ec_os_drop_cache(t);
        ec_ctr_free(c);
        c = NULL;
        if (pat == EC_RANDOM && !(c = ec_ctr_new(key))) {
            snprintf(err, EC_ERRLEN, "random generator failed");
            goto out;
        }
        for (uint64_t off = 0; off < size; off += CHUNK) {
            size_t n = size - off < CHUNK ? (size_t)(size - off) : CHUNK;
            if (fill(c, buf, n) || ec_os_pread(t, chk, n, off)) {
                snprintf(err, EC_ERRLEN, "read-back failed at offset %llu",
                         (unsigned long long)off);
                goto out;
            }
            if (memcmp(buf, chk, n)) {
                snprintf(err, EC_ERRLEN, "verification mismatch near offset %llu",
                         (unsigned long long)off);
                goto out;
            }
        }
    }
    rc = 0;
out:
    ec_ctr_free(c);
    memset(key, 0, sizeof key);
    ec_free_aligned(rb);
    ec_free_aligned(rc2);
    return rc;
}

int ec_wipe_path(const char *path, enum ec_pattern pat, int passes, int verify,
                 const char *confirm, ec_wipe_result *r)
{
    memset(r, 0, sizeof *r);
    ec_target t;
    if (ec_os_open(path, 1, confirm, &t, r->err))
        return -1;
    r->bytes = t.size;
    r->is_device = t.is_device;
    int rc = 0;
    for (int p = 0; p < passes && rc == 0; p++) {
        /* Verify only the final pass: earlier passes are overwritten anyway. */
        rc = ec_overwrite(&t, t.size, pat, verify && p == passes - 1, r->err);
        if (rc == 0)
            r->passes++;
    }
    r->verified = rc == 0 && verify;
    ec_os_close(&t);
    return rc;
}
