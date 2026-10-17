/* shred.c - file and folder erasure.
 * SPDX-License-Identifier: MIT
 *
 * Per file: overwrite contents in place (one random pass, optional read-back
 * verify), fsync, truncate, rename to a random name to scrub the directory
 * entry, unlink, fsync the parent directory. Symlinks are removed, never
 * followed. This only reaches the blocks the filesystem currently maps to
 * the file; see ec_fs_warning() and the README for the limits. */
#define _GNU_SOURCE
#include "erasecure.h"

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <limits.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

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

int ec_shred_file(const char *path, int verify, char err[EC_ERRLEN])
{
    struct stat st;
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
    int fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        snprintf(err, EC_ERRLEN, "open %s: %s", path, strerror(errno));
        return -1;
    }
    if (st.st_size > 0 &&
        ec_overwrite_fd(fd, (uint64_t)st.st_size, EC_RANDOM, verify, err)) {
        close(fd);
        return -1;
    }
    if (ftruncate(fd, 0) || fsync(fd)) {
        snprintf(err, EC_ERRLEN, "truncate %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);

    /* Rename to a random same-length-ish name before unlinking. */
    char dirbuf[PATH_MAX], tmp[PATH_MAX];
    snprintf(dirbuf, sizeof dirbuf, "%s", path);
    const char *dir = dirname(dirbuf);
    unsigned char rnd[8];
    if (RAND_bytes(rnd, sizeof rnd) != 1) {
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
    return 0;
}

/* nftw has no user pointer, so the walk state is file-scoped. */
static ec_shred_stats *g_st;
static int g_verify;

static int visit(const char *p, const struct stat *sb, int type, struct FTW *f)
{
    (void)f;
    char err[EC_ERRLEN];
    int rc = 0;
    if (type == FTW_F) {
        if ((rc = ec_shred_file(p, g_verify, err)) == 0) {
            g_st->files++;
            g_st->bytes += (uint64_t)sb->st_size;
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
