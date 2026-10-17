/* carve.c - signature + structure based file recovery from a raw image.
 * SPDX-License-Identifier: MIT
 *
 * Read-only: the image is mmap'd PROT_READ. Each candidate header is
 * validated by walking the format's real structure (JPEG markers, PNG
 * chunks, ZIP end-of-central-directory) rather than just grabbing bytes up
 * to the first footer, which cuts down false positives and truncation.
 * Fragmented files are not reassembled: only contiguous files are recovered. */
#define _GNU_SOURCE
#include "erasecure.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

enum { T_JPG, T_PNG, T_GIF, T_PDF, T_ZIP, T_N };
static const char *ext[T_N] = {"jpg", "png", "gif", "pdf", "zip"};

const char *ec_carve_type_name(int i) { return i >= 0 && i < T_N ? ext[i] : NULL; }

static const unsigned char *find(const unsigned char *p, const unsigned char *end,
                                 const char *needle, size_t n)
{
    return p < end ? memmem(p, (size_t)(end - p), needle, n) : NULL;
}

static uint32_t be32(const unsigned char *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* Each returns the file length, or 0 if the structure doesn't hold up. */
static size_t len_jpg(const unsigned char *s, const unsigned char *end)
{
    const unsigned char *p = s + 2;
    while (p + 4 <= end) { /* header segments, skipped by their length */
        if (p[0] != 0xFF) return 0;
        unsigned m = p[1];
        if (m == 0xFF) { p++; continue; }           /* fill byte */
        unsigned seg = (unsigned)p[2] << 8 | p[3];
        if (seg < 2) return 0;
        p += 2 + seg;
        if (m == 0xDA) break;                       /* start of scan */
    }
    for (; p + 1 < end; p++) {                      /* entropy-coded data */
        if (p[0] != 0xFF) continue;
        unsigned m = p[1];
        if (m == 0xD9) return (size_t)(p + 2 - s);  /* EOI */
        if (m == 0x00 || (m >= 0xD0 && m <= 0xD7) || m == 0xFF) continue;
        if (m == 0xDA || (m >= 0xC0 && m <= 0xFE)) { /* progressive: next segment */
            if (p + 4 > end) return 0;
            p += 1 + ((unsigned)p[2] << 8 | p[3]);
        }
    }
    return 0;
}

static size_t len_png(const unsigned char *s, const unsigned char *end)
{
    const unsigned char *p = s + 8;
    while (p + 12 <= end) {
        uint32_t n = be32(p);
        for (int i = 4; i < 8; i++)
            if (!((p[i] | 0x20) >= 'a' && (p[i] | 0x20) <= 'z')) return 0;
        if (n > (uint32_t)(end - p) - 12) return 0;
        int iend = !memcmp(p + 4, "IEND", 4);
        p += 12 + n;
        if (iend) return (size_t)(p - s);
    }
    return 0;
}

static size_t len_gif(const unsigned char *s, const unsigned char *end)
{
    const unsigned char *t = find(s + 13, end, "\x00\x3B", 2);
    return t ? (size_t)(t + 2 - s) : 0;
}

static size_t len_pdf(const unsigned char *s, const unsigned char *end)
{
    /* Incremental saves append more %%EOF markers: take the last one before
     * the next PDF header. */
    const unsigned char *next = find(s + 5, end, "%PDF-", 5);
    const unsigned char *lim = next ? next : end, *last = NULL, *t = s;
    while ((t = find(t + 1, lim, "%%EOF", 5)))
        last = t;
    if (!last) return 0;
    last += 5;
    while (last < lim && (*last == '\r' || *last == '\n')) last++;
    return (size_t)(last - s);
}

static size_t len_zip(const unsigned char *s, const unsigned char *end)
{
    const unsigned char *e = find(s + 4, end, "PK\x05\x06", 4);
    if (!e || e + 22 > end) return 0;
    size_t total = (size_t)(e - s) + 22 + (size_t)(e[20] | e[21] << 8);
    return s + total <= end ? total : 0;
}

static const struct { const char *magic; size_t n; int type; } sigs[] = {
    {"\xFF\xD8\xFF", 3, T_JPG},
    {"\x89PNG\r\n\x1a\n", 8, T_PNG},
    {"GIF87a", 6, T_GIF},
    {"GIF89a", 6, T_GIF},
    {"%PDF-", 5, T_PDF},
    {"PK\x03\x04", 4, T_ZIP},
};

static size_t measure(int t, const unsigned char *s, const unsigned char *end)
{
    switch (t) {
    case T_JPG: return len_jpg(s, end);
    case T_PNG: return len_png(s, end);
    case T_GIF: return len_gif(s, end);
    case T_PDF: return len_pdf(s, end);
    default:    return len_zip(s, end);
    }
}

static int save(const char *dir, uint64_t off, int t, const unsigned char *p, size_t n)
{
    char path[4096];
    snprintf(path, sizeof path, "%s/%012llx.%s", dir, (unsigned long long)off, ext[t]);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0640);
    if (fd < 0)
        return -1;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) { close(fd); return -1; }
        p += w; n -= (size_t)w;
    }
    return close(fd);
}

int ec_carve(const char *image, const char *outdir, uint64_t max_file,
             ec_carve_stats *st)
{
    memset(st, 0, sizeof *st);
    int fd = open(image, O_RDONLY | O_CLOEXEC);
    struct stat sb;
    if (fd < 0 || fstat(fd, &sb) || sb.st_size == 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    size_t size = (size_t)sb.st_size;
    const unsigned char *img = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (img == MAP_FAILED)
        return -1;
    madvise((void *)img, size, MADV_SEQUENTIAL);
    if (mkdir(outdir, 0750) && errno != EEXIST) {
        munmap((void *)img, size);
        return -1;
    }

    const unsigned char *end = img + size;
    int rc = 0;
    for (const unsigned char *p = img; p < end; ) {
        size_t got = 0;
        for (size_t i = 0; i < sizeof sigs / sizeof *sigs && !got; i++) {
            if ((size_t)(end - p) < sigs[i].n || memcmp(p, sigs[i].magic, sigs[i].n))
                continue;
            const unsigned char *lim = (uint64_t)(end - p) > max_file ? p + max_file : end;
            got = measure(sigs[i].type, p, lim);
            if (got && save(outdir, (uint64_t)(p - img), sigs[i].type, p, got) == 0) {
                st->found++;
                st->by_type[sigs[i].type]++;
            } else if (got) {
                rc = -1;
            }
        }
        p += got ? got : 1;
    }
    munmap((void *)img, size);
    return rc;
}
