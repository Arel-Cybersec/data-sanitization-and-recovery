/* os_linux.c - Linux platform layer: device access, discovery, shredding.
 * SPDX-License-Identifier: MIT
 *
 * Device guidance follows NIST SP 800-88 Rev. 2 (Sept 2025): Clear / Purge /
 * Destroy by data sensitivity; one overwrite pass suffices for Clear where
 * overwrite is supported; flash media need device-native sanitize for Purge.
 * EraseCure performs Clear; Purge commands are printed, not run. */
#define _GNU_SOURCE
#include "erasecure.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

/* ---------- file / device I/O ---------- */

/* 1 if /dev/<devname> or one of its partitions is mounted or active swap. */
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

int ec_os_open(const char *path, int write, const char *confirm, ec_target *t,
               char err[EC_ERRLEN])
{
    memset(t, 0, sizeof *t);
    t->h = -1;
    t->sector = 512;
    char real[PATH_MAX];
    struct stat st;
    if (!realpath(path, real) || stat(real, &st)) {
        snprintf(err, EC_ERRLEN, "%s: %s", path, strerror(errno));
        return -1;
    }
    t->is_device = S_ISBLK(st.st_mode);
    if (t->is_device && write) {
        if (!confirm || strcmp(confirm, real)) {
            snprintf(err, EC_ERRLEN,
                     "refusing to wipe drive %s without --confirm %s", real, real);
            return -1;
        }
        if (ec_device_is_mounted(strrchr(real, '/') + 1)) {
            snprintf(err, EC_ERRLEN,
                     "%s (or a partition on it) is mounted or used as swap", real);
            return -1;
        }
    } else if (!t->is_device && !S_ISREG(st.st_mode)) {
        snprintf(err, EC_ERRLEN, "%s is not a regular file or drive", real);
        return -1;
    }
    int fd = open(real, (write ? O_RDWR : O_RDONLY) | O_CLOEXEC |
                            (t->is_device && write ? O_EXCL : 0));
    if (fd < 0) {
        snprintf(err, EC_ERRLEN, "open %s: %s", real, strerror(errno));
        return -1;
    }
    t->h = fd;
    t->size = (uint64_t)st.st_size;
    if (t->is_device) {
        int ss = 512;
        if (ioctl(fd, BLKGETSIZE64, &t->size)) {
            snprintf(err, EC_ERRLEN, "BLKGETSIZE64: %s", strerror(errno));
            ec_os_close(t);
            return -1;
        }
        if (ioctl(fd, BLKSSZGET, &ss) == 0 && ss > 0)
            t->sector = (unsigned)ss;
    }
    return 0;
}

int ec_os_pread(ec_target *t, void *buf, size_t n, uint64_t off)
{
    unsigned char *b = buf;
    while (n) {
        ssize_t r = pread((int)t->h, b, n, (off_t)off);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        b += r; n -= (size_t)r; off += (uint64_t)r;
    }
    return 0;
}

int ec_os_pwrite(ec_target *t, const void *buf, size_t n, uint64_t off)
{
    const unsigned char *b = buf;
    while (n) {
        ssize_t w = pwrite((int)t->h, b, n, (off_t)off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        b += w; n -= (size_t)w; off += (uint64_t)w;
    }
    return 0;
}

int ec_os_sync(ec_target *t) { return fsync((int)t->h); }

/* Drop cached pages so verification reads come from the device. */
void ec_os_drop_cache(ec_target *t) { posix_fadvise((int)t->h, 0, 0, POSIX_FADV_DONTNEED); }

void ec_os_close(ec_target *t)
{
    if (t->h >= 0) close((int)t->h);
    t->h = -1;
}

FILE *ec_os_fopen(const char *path, const char *mode) { return fopen(path, mode); }

FILE *ec_os_create_excl(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0640);
    FILE *f = fd < 0 ? NULL : fdopen(fd, "wb");
    if (fd >= 0 && !f) close(fd);
    return f;
}

int ec_os_mkdir(const char *path) { return mkdir(path, 0750) && errno != EEXIST ? -1 : 0; }

int ec_os_is_dir(const char *path)
{
    struct stat st;
    return lstat(path, &st) ? -1 : S_ISDIR(st.st_mode);
}

const unsigned char *ec_os_map(const char *path, uint64_t *size, void **cookie)
{
    *cookie = NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || st.st_size == 0) {
        if (fd >= 0) close(fd);
        return NULL;
    }
    *size = (uint64_t)st.st_size;
    void *p = mmap(NULL, (size_t)*size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED)
        return NULL;
    madvise(p, (size_t)*size, MADV_SEQUENTIAL);
    return p;
}

void ec_os_unmap(const unsigned char *p, uint64_t size, void *cookie)
{
    (void)cookie;
    munmap((void *)p, (size_t)size);
}

void ec_os_lock(FILE *f) { flock(fileno(f), LOCK_EX); }

int ec_os_fsync(FILE *f) { return fflush(f) || fsync(fileno(f)) ? -1 : 0; }

/* ---------- device discovery ---------- */

static int read_attr(const char *dev, const char *attr, char *out, size_t n)
{
    char p[PATH_MAX];
    snprintf(p, sizeof p, "/sys/block/%s/%s", dev, attr);
    FILE *f = fopen(p, "r");
    if (!f)
        return -1;
    char *ok = fgets(out, (int)n, f);
    fclose(f);
    if (!ok)
        return -1;
    out[strcspn(out, "\n")] = 0;
    while (*out && out[strlen(out) - 1] == ' ')
        out[strlen(out) - 1] = 0;
    return 0;
}

const char *ec_classify(const char *name, int rotational, int usb)
{
    if (!strncmp(name, "nvme", 4)) return "NVMe SSD";
    if (!strncmp(name, "mmcblk", 6)) return "SD/eMMC";
    if (!strncmp(name, "vd", 2) || !strncmp(name, "xvd", 3)) return "Virtual disk";
    if (usb) return rotational ? "USB HDD" : "USB flash/SSD";
    return rotational ? "HDD" : "SATA/SAS SSD";
}

static const char *advice(const char *type)
{
    if (!strcmp(type, "HDD") || !strcmp(type, "USB HDD"))
        return "Clear: erasecure wipe (1 pass). Purge: ATA Secure Erase "
               "(hdparm --security-erase) or degauss.";
    if (!strcmp(type, "NVMe SSD"))
        return "Purge: nvme sanitize /dev/nvmeX --sanact=start-crypto-erase "
               "(or start-block-erase), then nvme sanitize-log /dev/nvmeX.";
    if (!strcmp(type, "SATA/SAS SSD"))
        return "Purge: drive's ATA SANITIZE (block erase / crypto scramble) "
               "or ATA Secure Erase via vendor tool or hdparm.";
    if (!strcmp(type, "Virtual disk"))
        return "Physical media is not reachable from a VM: use the provider's "
               "cryptographic erase / volume deletion for Purge.";
    return "No reliable Purge command for most cards/sticks: overwrite is "
           "Clear at best; Destroy for moderate/high data.";
}

int ec_os_list_devices(void)
{
    DIR *d = opendir("/sys/block");
    if (!d) {
        perror("/sys/block");
        return -1;
    }
    printf("%-14s %-14s %10s  %-24s %s\n", "DRIVE", "TYPE", "SIZE", "MODEL", "IN USE");
    struct dirent *e;
    int n = 0;
    while ((e = readdir(d))) {
        const char *nm = e->d_name;
        if (nm[0] == '.' || !strncmp(nm, "loop", 4) || !strncmp(nm, "ram", 3) ||
            !strncmp(nm, "zram", 4) || !strncmp(nm, "dm-", 3) ||
            !strncmp(nm, "md", 2) || !strncmp(nm, "sr", 2))
            continue;
        char rot[8] = "0", size[32] = "0", model[64] = "-", p[PATH_MAX], real[PATH_MAX];
        read_attr(nm, "queue/rotational", rot, sizeof rot);
        read_attr(nm, "size", size, sizeof size);
        read_attr(nm, "device/model", model, sizeof model);
        snprintf(p, sizeof p, "/sys/block/%s", nm);
        int usb = realpath(p, real) && strstr(real, "/usb");
        const char *type = ec_classify(nm, rot[0] == '1', usb);
        double gb = strtod(size, NULL) * 512.0 / 1e9; /* sysfs size is 512-byte units */
        printf("/dev/%-9s %-14s %8.1fGB  %-24.24s %s\n", nm, type, gb, model,
               ec_device_is_mounted(nm) ? "yes" : "no");
        printf("               -> %s\n", advice(type));
        n++;
    }
    closedir(d);
    if (!n)
        puts("(no physical drives visible)");
    return 0;
}

/* ---------- shredding ---------- */

const char *ec_fs_warning(const char *path)
{
    struct statfs s;
    if (statfs(path, &s))
        return NULL;
    switch ((unsigned long)s.f_type) {
    case 0x9123683EUL: return "btrfs is copy-on-write: old file blocks may survive an in-place overwrite";
    case 0x2FC12FC1UL: return "ZFS is copy-on-write: old file blocks may survive an in-place overwrite";
    case 0x58465342UL: return "XFS may keep old data in reflinked or reallocated extents";
    case 0x01021994UL: return "tmpfs lives in RAM/swap: overwrite is best-effort only";
    default: return NULL;
    }
}

/* Overwrite in place, truncate, rename to a random name (scrubs the
 * directory entry), unlink, fsync the parent. Symlinks are never followed. */
int ec_shred_file(const char *path, int verify, uint64_t *bytes, char err[EC_ERRLEN])
{
    struct stat st;
    *bytes = 0;
    if (lstat(path, &st)) {
        snprintf(err, EC_ERRLEN, "%s: %s", path, strerror(errno));
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        snprintf(err, EC_ERRLEN, "%s is not a regular file", path);
        return -1;
    }
    if (st.st_nlink > 1) {
        snprintf(err, EC_ERRLEN, "%s has %lu hard links; content is shared, skipping",
                 path, (unsigned long)st.st_nlink);
        return -1;
    }
    ec_target t = {.h = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC), .sector = 512};
    if (t.h < 0) {
        snprintf(err, EC_ERRLEN, "open %s: %s", path, strerror(errno));
        return -1;
    }
    if (st.st_size > 0 && ec_overwrite(&t, (uint64_t)st.st_size, EC_RANDOM, verify, err)) {
        ec_os_close(&t);
        return -1;
    }
    if (ftruncate((int)t.h, 0) || fsync((int)t.h)) {
        snprintf(err, EC_ERRLEN, "truncate %s: %s", path, strerror(errno));
        ec_os_close(&t);
        return -1;
    }
    ec_os_close(&t);

    char dirbuf[PATH_MAX], tmp[PATH_MAX];
    unsigned char rnd[8];
    snprintf(dirbuf, sizeof dirbuf, "%s", path);
    const char *dir = dirname(dirbuf);
    if (ec_random(rnd, sizeof rnd)) {
        snprintf(err, EC_ERRLEN, "random generator failed");
        return -1;
    }
    int n = snprintf(tmp, sizeof tmp, "%s/", dir);
    for (int i = 0; i < 8 && n < (int)sizeof tmp - 3; i++)
        n += snprintf(tmp + n, sizeof tmp - (size_t)n, "%02x", rnd[i]);
    const char *victim = rename(path, tmp) == 0 ? tmp : path;
    if (unlink(victim)) {
        snprintf(err, EC_ERRLEN, "unlink %s: %s", victim, strerror(errno));
        return -1;
    }
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) {
        fsync(dfd);
        close(dfd);
    }
    *bytes = (uint64_t)st.st_size;
    return 0;
}

/* nftw has no user pointer, so the walk state is file-scoped. */
static ec_shred_stats *g_st;
static int g_verify;

static int visit(const char *p, const struct stat *sb, int type, struct FTW *f)
{
    (void)f; (void)sb;
    char err[EC_ERRLEN];
    uint64_t b;
    int rc = 0;
    if (type == FTW_F) {
        if ((rc = ec_shred_file(p, g_verify, &b, err)) == 0) {
            g_st->files++;
            g_st->bytes += b;
        } else {
            fprintf(stderr, "  ! %s\n", err);
        }
    } else if (type == FTW_SL || type == FTW_SLN) {
        if ((rc = unlink(p)) == 0)
            g_st->links++;
    } else if (type == FTW_DP) {
        if ((rc = rmdir(p)) == 0)
            g_st->dirs++;
        else
            fprintf(stderr, "  ! rmdir %s: %s\n", p, strerror(errno));
    } else {
        fprintf(stderr, "  ! cannot access %s\n", p);
        rc = -1;
    }
    if (rc)
        g_st->failed++;
    return 0; /* keep going; failures are counted */
}

int ec_shred_tree(const char *path, int verify, ec_shred_stats *st)
{
    memset(st, 0, sizeof *st);
    g_st = st;
    g_verify = verify;
    /* FTW_PHYS: never follow symlinks. FTW_MOUNT: stay on one filesystem. */
    if (nftw(path, visit, 32, FTW_DEPTH | FTW_PHYS | FTW_MOUNT))
        return -1;
    return st->failed ? -1 : 0;
}
