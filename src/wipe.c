/* wipe.c - single/multi-pass overwrite with read-back verification.
 * SPDX-License-Identifier: MIT
 *
 * Random data is an AES-256-CTR keystream under a fresh random key per pass.
 * It is fast, unpredictable to anyone without the key, and reproducible, so
 * verification regenerates the exact stream and compares every byte. */
#define _GNU_SOURCE
#include "erasecure.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHUNK (1u << 20) /* 1 MiB */

typedef struct {
    enum ec_pattern pat;
    EVP_CIPHER_CTX *ctx;
    unsigned char key[32];
} stream;

static int stream_start(stream *s, enum ec_pattern pat, int new_key)
{
    static const unsigned char iv[16] = {0};
    s->pat = pat;
    if (pat != EC_RANDOM)
        return 0;
    if (new_key && RAND_bytes(s->key, sizeof s->key) != 1)
        return -1;
    if (!s->ctx && !(s->ctx = EVP_CIPHER_CTX_new()))
        return -1;
    return EVP_EncryptInit_ex(s->ctx, EVP_aes_256_ctr(), NULL, s->key, iv) == 1
               ? 0 : -1;
}

/* Fill buf with the next n bytes of the pattern. */
static int stream_fill(stream *s, unsigned char *buf, size_t n)
{
    memset(buf, 0, n);
    if (s->pat != EC_RANDOM)
        return 0;
    int out = 0;
    return EVP_EncryptUpdate(s->ctx, buf, &out, buf, (int)n) == 1 &&
                   (size_t)out == n ? 0 : -1;
}

static void stream_end(stream *s)
{
    EVP_CIPHER_CTX_free(s->ctx);
    s->ctx = NULL;
    OPENSSL_cleanse(s->key, sizeof s->key);
}

static int full_pwrite(int fd, const unsigned char *b, size_t n, off_t off)
{
    while (n) {
        ssize_t w = pwrite(fd, b, n, off);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return -1;
        b += w; n -= (size_t)w; off += w;
    }
    return 0;
}

static int full_pread(int fd, unsigned char *b, size_t n, off_t off)
{
    while (n) {
        ssize_t r = pread(fd, b, n, off);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            return -1;
        b += r; n -= (size_t)r; off += r;
    }
    return 0;
}

static int one_pass(int fd, uint64_t size, stream *s, unsigned char *buf,
                    unsigned char *chk, int verify, char err[EC_ERRLEN])
{
    if (stream_start(s, s->pat, 1)) {
        snprintf(err, EC_ERRLEN, "random generator failed");
        return -1;
    }
    for (uint64_t off = 0; off < size; off += CHUNK) {
        size_t n = size - off < CHUNK ? (size_t)(size - off) : CHUNK;
        if (stream_fill(s, buf, n) || full_pwrite(fd, buf, n, (off_t)off)) {
            snprintf(err, EC_ERRLEN, "write failed at offset %llu: %s",
                     (unsigned long long)off, strerror(errno));
            return -1;
        }
    }
    if (fsync(fd)) {
        snprintf(err, EC_ERRLEN, "fsync failed: %s", strerror(errno));
        return -1;
    }
    if (!verify)
        return 0;

    /* Drop our cached pages so reads come from the device where possible. */
    posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
    if (stream_start(s, s->pat, 0))
        return -1;
    for (uint64_t off = 0; off < size; off += CHUNK) {
        size_t n = size - off < CHUNK ? (size_t)(size - off) : CHUNK;
        if (stream_fill(s, buf, n) || full_pread(fd, chk, n, (off_t)off)) {
            snprintf(err, EC_ERRLEN, "read-back failed at offset %llu",
                     (unsigned long long)off);
            return -1;
        }
        if (memcmp(buf, chk, n)) {
            snprintf(err, EC_ERRLEN, "verification mismatch near offset %llu",
                     (unsigned long long)off);
            return -1;
        }
    }
    return 0;
}

int ec_overwrite_fd(int fd, uint64_t size, enum ec_pattern pat, int verify,
                    char err[EC_ERRLEN])
{
    unsigned char *buf = malloc(CHUNK), *chk = malloc(CHUNK);
    stream s = {.pat = pat};
    int rc = -1;
    if (!buf || !chk)
        snprintf(err, EC_ERRLEN, "out of memory");
    else
        rc = one_pass(fd, size, &s, buf, chk, verify, err);
    stream_end(&s);
    free(buf);
    free(chk);
    return rc;
}

/* 1 if /dev/<devname> or one of its partitions appears in /proc/mounts or
 * is an active swap device. */
int ec_device_is_mounted(const char *devname)
{
    const char *files[] = {"/proc/mounts", "/proc/swaps"};
    char line[1024], src[512], real[PATH_MAX], sys[PATH_MAX];
    for (int f = 0; f < 2; f++) {
        FILE *fp = fopen(files[f], "r");
        if (!fp)
            continue;
        while (fgets(line, sizeof line, fp)) {
            if (sscanf(line, "%511s", src) != 1 || strncmp(src, "/dev/", 5))
                continue;
            const char *b = realpath(src, real) ? real : src;
            b = strrchr(b, '/') + 1;
            snprintf(sys, sizeof sys, "/sys/block/%s/%s", devname, b);
            if (!strcmp(b, devname) || access(sys, F_OK) == 0) {
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }
    return 0;
}

int ec_wipe_path(const char *path, enum ec_pattern pat, int passes, int verify,
                 const char *confirm, ec_wipe_result *r)
{
    memset(r, 0, sizeof *r);
    char real[PATH_MAX];
    struct stat st;
    if (!realpath(path, real) || stat(real, &st)) {
        snprintf(r->err, EC_ERRLEN, "%s: %s", path, strerror(errno));
        return -1;
    }
    if (S_ISBLK(st.st_mode)) {
        const char *name = strrchr(real, '/') + 1;
        if (!confirm || strcmp(confirm, real)) {
            snprintf(r->err, EC_ERRLEN,
                     "refusing to wipe block device %s without --confirm %s",
                     real, real);
            return -1;
        }
        if (ec_device_is_mounted(name)) {
            snprintf(r->err, EC_ERRLEN,
                     "%s (or a partition on it) is mounted or used as swap",
                     real);
            return -1;
        }
    } else if (!S_ISREG(st.st_mode)) {
        snprintf(r->err, EC_ERRLEN, "%s is not a regular file or block device",
                 real);
        return -1;
    }

    int fd = open(real, O_RDWR | O_CLOEXEC | (S_ISBLK(st.st_mode) ? O_EXCL : 0));
    if (fd < 0) {
        snprintf(r->err, EC_ERRLEN, "open %s: %s", real, strerror(errno));
        return -1;
    }
    r->bytes = (uint64_t)st.st_size;
    if (S_ISBLK(st.st_mode) && ioctl(fd, BLKGETSIZE64, &r->bytes)) {
        snprintf(r->err, EC_ERRLEN, "BLKGETSIZE64: %s", strerror(errno));
        close(fd);
        return -1;
    }
    int rc = 0;
    for (int p = 0; p < passes && rc == 0; p++) {
        /* Verify only the final pass: earlier passes are overwritten anyway. */
        rc = ec_overwrite_fd(fd, r->bytes, pat, verify && p == passes - 1, r->err);
        if (rc == 0)
            r->passes++;
    }
    r->verified = rc == 0 && verify;
    close(fd);
    return rc;
}
