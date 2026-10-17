/* image.c - read-only acquisition of a drive (or file) into an image file.
 * SPDX-License-Identifier: MIT
 *
 * Standard forensic order: image first, then carve the image, never the
 * original. The source is opened O_RDONLY and never written. Unreadable
 * sectors are retried one 512-byte sector at a time and zero-filled, so the
 * image keeps the same offsets as the source; the bad ranges are counted.
 * A SHA-256 of the image is computed while writing. */
#define _GNU_SOURCE
#include "erasecure.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHUNK (1u << 20)
#define SECTOR 512u

static ssize_t read_at(int fd, unsigned char *b, size_t n, off_t off)
{
    size_t done = 0;
    while (done < n) {
        ssize_t r = pread(fd, b + done, n - done, off + (off_t)done);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return r < 0 ? -1 : (ssize_t)done;
        done += (size_t)r;
    }
    return (ssize_t)done;
}

int ec_image(const char *src, const char *dst, ec_image_result *r)
{
    memset(r, 0, sizeof *r);
    struct stat st;
    int in = open(src, O_RDONLY | O_CLOEXEC);
    if (in < 0 || fstat(in, &st)) {
        snprintf(r->err, EC_ERRLEN, "%s: %s", src, strerror(errno));
        if (in >= 0) close(in);
        return -1;
    }
    r->bytes = (uint64_t)st.st_size;
    if (S_ISBLK(st.st_mode) && ioctl(in, BLKGETSIZE64, &r->bytes)) {
        snprintf(r->err, EC_ERRLEN, "BLKGETSIZE64: %s", strerror(errno));
        close(in);
        return -1;
    }
    int out = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0640);
    if (out < 0) {
        snprintf(r->err, EC_ERRLEN, "%s: %s", dst, strerror(errno));
        close(in);
        return -1;
    }
    unsigned char *buf = malloc(CHUNK), md[32];
    EVP_MD_CTX *h = EVP_MD_CTX_new();
    int rc = -1;
    if (!buf || !h || EVP_DigestInit_ex(h, EVP_sha256(), NULL) != 1) {
        snprintf(r->err, EC_ERRLEN, "out of memory");
        goto done;
    }
    for (uint64_t off = 0; off < r->bytes; off += CHUNK) {
        size_t n = r->bytes - off < CHUNK ? (size_t)(r->bytes - off) : CHUNK;
        if (read_at(in, buf, n, (off_t)off) != (ssize_t)n) {
            /* Retry sector by sector; zero-fill what still fails. */
            for (size_t s = 0; s < n; s += SECTOR) {
                size_t k = n - s < SECTOR ? n - s : SECTOR;
                if (read_at(in, buf + s, k, (off_t)(off + s)) != (ssize_t)k) {
                    memset(buf + s, 0, k);
                    r->bad_sectors++;
                }
            }
        }
        size_t w = 0;
        while (w < n) {
            ssize_t k = write(out, buf + w, n - w);
            if (k < 0 && errno == EINTR) continue;
            if (k <= 0) {
                snprintf(r->err, EC_ERRLEN, "write %s: %s", dst, strerror(errno));
                goto done;
            }
            w += (size_t)k;
        }
        EVP_DigestUpdate(h, buf, n);
    }
    if (fsync(out)) {
        snprintf(r->err, EC_ERRLEN, "fsync %s: %s", dst, strerror(errno));
        goto done;
    }
    EVP_DigestFinal_ex(h, md, NULL);
    for (int i = 0; i < 32; i++)
        sprintf(r->sha256 + 2 * i, "%02x", md[i]);
    rc = 0;
done:
    EVP_MD_CTX_free(h);
    free(buf);
    close(out);
    close(in);
    return rc;
}
