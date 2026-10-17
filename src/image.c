/* image.c - read-only acquisition of a drive (or file) into an image file.
 * SPDX-License-Identifier: MIT
 *
 * Standard forensic order: image first, then carve the image, never the
 * original. The source is opened read-only and never written. Unreadable
 * areas are retried one sector at a time and zero-filled, so the image keeps
 * the same offsets as the source; bad sectors are counted. A SHA-256 of the
 * image is computed while writing. */
#include "erasecure.h"

#include <stdlib.h>
#include <string.h>

#define CHUNK (1u << 20)

int ec_image(const char *src, const char *dst, ec_image_result *r)
{
    memset(r, 0, sizeof *r);
    ec_target t;
    if (ec_os_open(src, 0, NULL, &t, r->err))
        return -1;
    r->bytes = t.size;
    FILE *out = ec_os_create_excl(dst);
    if (!out) {
        snprintf(r->err, EC_ERRLEN, "cannot create %s (does it already exist?)", dst);
        ec_os_close(&t);
        return -1;
    }
    void *raw;
    unsigned char *buf = ec_alloc_aligned(CHUNK, &raw);
    ec_sha *h = ec_sha_new();
    int rc = -1;
    if (!buf || !h) {
        snprintf(r->err, EC_ERRLEN, "out of memory");
        goto done;
    }
    for (uint64_t off = 0; off < t.size; off += CHUNK) {
        size_t n = t.size - off < CHUNK ? (size_t)(t.size - off) : CHUNK;
        if (ec_os_pread(&t, buf, n, off)) {
            /* Retry sector by sector; zero-fill what still fails. */
            for (size_t s = 0; s < n; s += t.sector) {
                size_t k = n - s < t.sector ? n - s : t.sector;
                if (ec_os_pread(&t, buf + s, k, off + s)) {
                    memset(buf + s, 0, k);
                    r->bad_sectors++;
                }
            }
        }
        if (fwrite(buf, 1, n, out) != n) {
            snprintf(r->err, EC_ERRLEN, "write %s failed (disk full?)", dst);
            goto done;
        }
        ec_sha_update(h, buf, n);
    }
    if (ec_os_fsync(out)) {
        snprintf(r->err, EC_ERRLEN, "flushing %s failed", dst);
        goto done;
    }
    rc = ec_sha_final(h, r->sha256);
    h = NULL;
done:
    if (h) ec_sha_final(h, r->sha256);
    ec_free_aligned(raw);
    fclose(out);
    ec_os_close(&t);
    return rc;
}
