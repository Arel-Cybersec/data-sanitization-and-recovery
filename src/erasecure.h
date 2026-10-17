/* erasecure.h - shared declarations for EraseCure 2.
 * SPDX-License-Identifier: MIT
 *
 * Portable core: wipe.c image.c carve.c audit.c main.c
 * Platform layer: os_linux.c | os_windows.c, crypto_openssl.c | crypto_windows.c */
#ifndef ERASECURE_H
#define ERASECURE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define EC_VERSION "2.2.0"
#define EC_ERRLEN 256

enum ec_pattern { EC_ZERO = 0, EC_RANDOM = 1 };

/* ---- crypto (OpenSSL on Linux, Windows CNG on Windows) ---- */
int ec_random(void *buf, size_t n);
int ec_sha256_hex(const void *data, size_t n, char out[65]);
typedef struct ec_sha ec_sha;
ec_sha *ec_sha_new(void);
int ec_sha_update(ec_sha *h, const void *data, size_t n);
int ec_sha_final(ec_sha *h, char out[65]); /* also frees h */
/* AES-256-CTR keystream: same key + same call sizes => same bytes. */
typedef struct ec_ctr ec_ctr;
ec_ctr *ec_ctr_new(const unsigned char key[32]);
int ec_ctr_stream(ec_ctr *c, unsigned char *buf, size_t n);
void ec_ctr_free(ec_ctr *c);

/* ---- platform layer ---- */
typedef struct {
    intptr_t h;         /* fd on Linux, HANDLE on Windows */
    uint64_t size;      /* bytes */
    unsigned sector;    /* I/O alignment for raw devices (512 for files) */
    int is_device;      /* whole drive rather than a file */
} ec_target;

/* write=1: wipe. A device needs confirm == its path and must be unused.
 * write=0: read-only open (imaging). */
int ec_os_open(const char *path, int write, const char *confirm, ec_target *t,
               char err[EC_ERRLEN]);
int ec_os_pread(ec_target *t, void *buf, size_t n, uint64_t off);  /* 0 = all read */
int ec_os_pwrite(ec_target *t, const void *buf, size_t n, uint64_t off);
int ec_os_sync(ec_target *t);
void ec_os_drop_cache(ec_target *t);
void ec_os_close(ec_target *t);
FILE *ec_os_create_excl(const char *path); /* "wb", fails if it exists */
FILE *ec_os_fopen(const char *path, const char *mode); /* UTF-8 path */
int ec_os_mkdir(const char *path);         /* 0 if created or exists */
int ec_os_is_dir(const char *path);        /* 1 dir, 0 other, -1 missing */
const unsigned char *ec_os_map(const char *path, uint64_t *size, void **cookie);
void ec_os_unmap(const unsigned char *p, uint64_t size, void *cookie);
void ec_os_lock(FILE *f);
int ec_os_fsync(FILE *f);              /* fflush + flush to disk */
int ec_os_list_devices(void);
const char *ec_fs_warning(const char *path);

/* ---- wipe.c ---- */
typedef struct {
    uint64_t bytes;
    int passes, verified, is_device;
    char err[EC_ERRLEN];
} ec_wipe_result;

/* 4 KiB-aligned buffer (unbuffered drive I/O needs sector alignment).
 * Free with ec_free_aligned(raw). */
void *ec_alloc_aligned(size_t n, void **raw);
#define ec_free_aligned(raw) free(raw)

int ec_overwrite(ec_target *t, uint64_t size, enum ec_pattern pat, int verify,
                 char err[EC_ERRLEN]);
int ec_wipe_path(const char *path, enum ec_pattern pat, int passes, int verify,
                 const char *confirm, ec_wipe_result *r);

/* ---- shred (in the os_*.c files) ---- */
typedef struct {
    unsigned files, dirs, links, failed;
    uint64_t bytes;
} ec_shred_stats;

int ec_shred_file(const char *path, int verify, uint64_t *bytes, char err[EC_ERRLEN]);
int ec_shred_tree(const char *path, int verify, ec_shred_stats *st);

/* ---- audit.c: tamper-evident SHA-256 hash chain (JSON Lines) ---- */
int ec_audit_append(const char *log, const char *action, const char *target,
                    const char *result, uint64_t bytes);
int ec_audit_verify(const char *log, long *bad_line);

/* ---- image.c ---- */
typedef struct {
    uint64_t bytes, bad_sectors;
    char sha256[65];
    char err[EC_ERRLEN];
} ec_image_result;

int ec_image(const char *src, const char *dst, ec_image_result *r);

/* ---- carve.c ---- */
typedef struct {
    unsigned found;
    unsigned by_type[8];
} ec_carve_stats;

int ec_carve(const char *image, const char *outdir, uint64_t max_file,
             ec_carve_stats *st);
const char *ec_carve_type_name(int i);

#ifdef _WIN32
char **ec_os_utf8_args(int *argc); /* the command line as UTF-8 */
int ec_gui_run(void);              /* gui_windows.c: the desktop window */
#endif
#ifdef __linux__
int ec_device_is_mounted(const char *devname);
const char *ec_classify(const char *name, int rotational, int usb);
#endif

#endif
