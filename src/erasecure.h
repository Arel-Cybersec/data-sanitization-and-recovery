/* erasecure.h - shared declarations for EraseCure 2.
 * SPDX-License-Identifier: MIT */
#ifndef ERASECURE_H
#define ERASECURE_H

#include <stddef.h>
#include <stdint.h>

#define EC_VERSION "2.0.0"
#define EC_ERRLEN 256

enum ec_pattern { EC_ZERO = 0, EC_RANDOM = 1 };

/* wipe.c - overwrite whole files or block devices */
typedef struct {
    uint64_t bytes;     /* size of target */
    int passes;         /* passes completed */
    int verified;       /* 1 = last pass read back and matched */
    char err[EC_ERRLEN];
} ec_wipe_result;

int ec_overwrite_fd(int fd, uint64_t size, enum ec_pattern pat, int verify,
                    char err[EC_ERRLEN]);
int ec_wipe_path(const char *path, enum ec_pattern pat, int passes, int verify,
                 const char *confirm, ec_wipe_result *r);
int ec_device_is_mounted(const char *devname);

/* shred.c - erase files/folders */
typedef struct {
    unsigned files, dirs, links, failed;
    uint64_t bytes;
} ec_shred_stats;

int ec_shred_file(const char *path, int verify, char err[EC_ERRLEN]);
int ec_shred_tree(const char *path, int verify, ec_shred_stats *st);
const char *ec_fs_warning(const char *path);

/* devices.c - discovery and NIST SP 800-88 Rev. 2 guidance */
int ec_list_devices(void);
const char *ec_classify(const char *name, int rotational, int usb);

/* audit.c - tamper-evident SHA-256 hash chain (JSON Lines) */
int ec_audit_append(const char *log, const char *action, const char *target,
                    const char *result, uint64_t bytes);
int ec_audit_verify(const char *log, long *bad_line);

/* image.c - read-only drive imaging */
typedef struct {
    uint64_t bytes, bad_sectors;
    char sha256[65];
    char err[EC_ERRLEN];
} ec_image_result;

int ec_image(const char *src, const char *dst, ec_image_result *r);

/* carve.c - signature-based recovery */
typedef struct {
    unsigned found;
    unsigned by_type[8];
} ec_carve_stats;

int ec_carve(const char *image, const char *outdir, uint64_t max_file,
             ec_carve_stats *st);
const char *ec_carve_type_name(int i);

#endif
