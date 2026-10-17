/* os_windows.c - Windows platform layer: drive access, discovery, shredding.
 * SPDX-License-Identifier: MIT
 *
 * Drives are \\.\PhysicalDriveN (numbers as in Get-Disk / Disk Management).
 * Safety: a drive is only ever written when it has NO volumes at all, so the
 * system disk and anything with a partition on it are refused. Clear a disk
 * deliberately first (Clear-Disk -Number N -RemoveData) to wipe it.
 * Raw drive handles use FILE_FLAG_NO_BUFFERING, so I/O goes straight to the
 * device; callers pass sector-aligned buffers, offsets and sizes.
 * Paths are UTF-8 inside the program and converted to UTF-16 for the
 * Win32 "W" APIs, so any file name works on every Windows version. */
#include "erasecure.h"

#include <windows.h>
#include <shellapi.h>
#include <winioctl.h>
#include <fcntl.h>
#include <io.h>
#include <stdlib.h>
#include <string.h>

static wchar_t *wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w = n > 0 ? malloc((size_t)n * sizeof *w) : NULL;
    if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

static void utf8(const wchar_t *w, char *out, int n)
{
    if (!WideCharToMultiByte(CP_UTF8, 0, w, -1, out, n, NULL, NULL)) out[0] = 0;
}

/* UTF-8 wrappers over the wide-char Win32 calls we need. */
static DWORD attrs(const char *p)
{
    wchar_t *w = wide(p);
    DWORD a = w ? GetFileAttributesW(w) : INVALID_FILE_ATTRIBUTES;
    free(w);
    return a;
}
static BOOL set_attrs(const char *p, DWORD a)
{
    wchar_t *w = wide(p);
    BOOL ok = w && SetFileAttributesW(w, a);
    free(w);
    return ok;
}
static HANDLE open_u(const char *p, DWORD acc, DWORD share, DWORD disp, DWORD flags)
{
    wchar_t *w = wide(p);
    HANDLE h = w ? CreateFileW(w, acc, share, NULL, disp, flags, NULL) : INVALID_HANDLE_VALUE;
    free(w);
    return h;
}
#define ONE_PATH(name, call) static BOOL name(const char *p) \
    { wchar_t *w = wide(p); BOOL ok = w && call; free(w); return ok; }
ONE_PATH(delete_u, DeleteFileW(w))
ONE_PATH(rmdir_u, RemoveDirectoryW(w))
ONE_PATH(mkdir_u, CreateDirectoryW(w, NULL))

static BOOL move_u(const char *a, const char *b)
{
    wchar_t *wa = wide(a), *wb = wide(b);
    BOOL ok = wa && wb && MoveFileExW(wa, wb, MOVEFILE_WRITE_THROUGH);
    free(wa);
    free(wb);
    return ok;
}

static void winerr(char err[EC_ERRLEN], const char *what)
{
    DWORD e = GetLastError();
    wchar_t wmsg[160] = L"";
    char msg[480];
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, e,
                   0, wmsg, 160, NULL);
    utf8(wmsg, msg, sizeof msg);
    msg[strcspn(msg, "\r\n")] = 0;
    snprintf(err, EC_ERRLEN, "%s: %s (error %lu)", what, msg, (unsigned long)e);
}

/* "\\.\PhysicalDrive3" -> 3, anything else -> -1 */
static int drive_number(const char *path)
{
    static const char pre[] = "\\\\.\\PhysicalDrive";
    if (_strnicmp(path, pre, sizeof pre - 1))
        return -1;
    const char *d = path + sizeof pre - 1;
    if (*d < '0' || *d > '9')
        return -1;
    return atoi(d);
}

/* 1 if any volume (mounted or not) has an extent on disk n; -1 if unknown. */
static int disk_has_volumes(int n)
{
    char vol[MAX_PATH];
    HANDLE f = FindFirstVolumeA(vol, sizeof vol);
    if (f == INVALID_HANDLE_VALUE)
        return -1;
    int found = 0;
    do {
        size_t len = strlen(vol);
        if (len && vol[len - 1] == '\\')
            vol[len - 1] = 0; /* open the volume, not its root folder */
        HANDLE v = CreateFileA(vol, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_EXISTING, 0, NULL);
        if (v == INVALID_HANDLE_VALUE)
            continue;
        union { VOLUME_DISK_EXTENTS x; char pad[sizeof(VOLUME_DISK_EXTENTS) + 32 * sizeof(DISK_EXTENT)]; } u;
        DWORD got;
        if (DeviceIoControl(v, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, &u, sizeof u,
                            &got, NULL))
            for (DWORD i = 0; i < u.x.NumberOfDiskExtents && i < 33; i++)
                if (u.x.Extents[i].DiskNumber == (DWORD)n)
                    found = 1;
        CloseHandle(v);
    } while (!found && FindNextVolumeA(f, vol, sizeof vol));
    FindVolumeClose(f);
    return found;
}

int ec_os_open(const char *path, int write, const char *confirm, ec_target *t,
               char err[EC_ERRLEN])
{
    memset(t, 0, sizeof *t);
    t->h = (intptr_t)INVALID_HANDLE_VALUE;
    t->sector = 512;
    int n = drive_number(path);
    t->is_device = n >= 0;
    DWORD access = GENERIC_READ | (write ? GENERIC_WRITE : 0);
    HANDLE h;
    if (t->is_device) {
        if (write) {
            if (!confirm || _stricmp(confirm, path)) {
                snprintf(err, EC_ERRLEN,
                         "refusing to wipe drive %s without --confirm %s", path, path);
                return -1;
            }
            int used = disk_has_volumes(n);
            if (used) {
                snprintf(err, EC_ERRLEN,
                         used < 0 ? "cannot check whether %s is in use"
                                  : "%s still has partitions/volumes. If you are sure, "
                                    "run (as Administrator) Clear-Disk -Number %d -RemoveData, "
                                    "then wipe again",
                         path, n);
                return -1;
            }
        }
        h = CreateFileA(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            winerr(err, GetLastError() == ERROR_ACCESS_DENIED
                            ? "drive access needs PowerShell opened as Administrator" : path);
            return -1;
        }
        DISK_GEOMETRY_EX g;
        DWORD got;
        if (!DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &g, sizeof g,
                             &got, NULL)) {
            winerr(err, "reading drive size");
            CloseHandle(h);
            return -1;
        }
        t->size = (uint64_t)g.DiskSize.QuadPart;
        if (g.Geometry.BytesPerSector)
            t->sector = g.Geometry.BytesPerSector;
    } else {
        DWORD a = attrs(path);
        if (a == INVALID_FILE_ATTRIBUTES) {
            winerr(err, path);
            return -1;
        }
        if (a & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) {
            snprintf(err, EC_ERRLEN, "%s is not a regular file or drive", path);
            return -1;
        }
        h = open_u(path, access, write ? 0 : FILE_SHARE_READ, OPEN_EXISTING,
                   write ? FILE_FLAG_WRITE_THROUGH : FILE_FLAG_SEQUENTIAL_SCAN);
        LARGE_INTEGER sz;
        if (h == INVALID_HANDLE_VALUE || !GetFileSizeEx(h, &sz)) {
            winerr(err, path);
            if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
            return -1;
        }
        t->size = (uint64_t)sz.QuadPart;
    }
    t->h = (intptr_t)h;
    return 0;
}

static int xfer(ec_target *t, void *buf, size_t n, uint64_t off, int write)
{
    unsigned char *b = buf;
    while (n) {
        OVERLAPPED o = {0};
        o.Offset = (DWORD)off;
        o.OffsetHigh = (DWORD)(off >> 32);
        DWORD k = n > (1u << 30) ? (1u << 30) : (DWORD)n, done = 0;
        BOOL ok = write ? WriteFile((HANDLE)t->h, b, k, &done, &o)
                        : ReadFile((HANDLE)t->h, b, k, &done, &o);
        if (!ok || done == 0)
            return -1;
        b += done; n -= done; off += done;
    }
    return 0;
}

int ec_os_pread(ec_target *t, void *buf, size_t n, uint64_t off) { return xfer(t, buf, n, off, 0); }
int ec_os_pwrite(ec_target *t, const void *buf, size_t n, uint64_t off) { return xfer(t, (void *)buf, n, off, 1); }
int ec_os_sync(ec_target *t) { return FlushFileBuffers((HANDLE)t->h) ? 0 : -1; }

/* ponytail: regular-file verify may be served from the Windows file cache;
 * unbuffered file I/O needs sector-sized tails. Drives are unbuffered already. */
void ec_os_drop_cache(ec_target *t) { (void)t; }

void ec_os_close(ec_target *t)
{
    if ((HANDLE)t->h != INVALID_HANDLE_VALUE) CloseHandle((HANDLE)t->h);
    t->h = (intptr_t)INVALID_HANDLE_VALUE;
}

FILE *ec_os_fopen(const char *path, const char *mode)
{
    wchar_t *wp = wide(path), *wm = wide(mode);
    FILE *f = wp && wm ? _wfopen(wp, wm) : NULL;
    free(wp);
    free(wm);
    return f;
}

char **ec_os_utf8_args(int *argc)
{
    wchar_t **wa = CommandLineToArgvW(GetCommandLineW(), argc);
    char **a = wa ? calloc((size_t)*argc + 1, sizeof *a) : NULL;
    for (int i = 0; a && i < *argc; i++) {
        int n = WideCharToMultiByte(CP_UTF8, 0, wa[i], -1, NULL, 0, NULL, NULL);
        if ((a[i] = malloc((size_t)n)))
            WideCharToMultiByte(CP_UTF8, 0, wa[i], -1, a[i], n, NULL, NULL);
    }
    LocalFree(wa);
    return a; /* lives for the whole run */
}

FILE *ec_os_create_excl(const char *path)
{
    HANDLE h = open_u(path, GENERIC_WRITE, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL);
    if (h == INVALID_HANDLE_VALUE)
        return NULL;
    int fd = _open_osfhandle((intptr_t)h, _O_WRONLY | _O_BINARY);
    if (fd < 0) {
        CloseHandle(h);
        return NULL;
    }
    FILE *f = _fdopen(fd, "wb");
    if (!f) _close(fd);
    return f;
}

int ec_os_mkdir(const char *path)
{
    return mkdir_u(path) || GetLastError() == ERROR_ALREADY_EXISTS ? 0 : -1;
}

int ec_os_is_dir(const char *path)
{
    DWORD a = attrs(path);
    if (a == INVALID_FILE_ATTRIBUTES) return -1;
    return (a & FILE_ATTRIBUTE_DIRECTORY) && !(a & FILE_ATTRIBUTE_REPARSE_POINT);
}

const unsigned char *ec_os_map(const char *path, uint64_t *size, void **cookie)
{
    *cookie = NULL;
    HANDLE f = open_u(path, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
                      FILE_FLAG_SEQUENTIAL_SCAN);
    LARGE_INTEGER sz;
    if (f == INVALID_HANDLE_VALUE)
        return NULL;
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart == 0) {
        CloseHandle(f);
        return NULL;
    }
    HANDLE m = CreateFileMappingW(f, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(f); /* the mapping keeps the file open */
    if (!m)
        return NULL;
    const unsigned char *p = MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    if (!p) {
        CloseHandle(m);
        return NULL;
    }
    *size = (uint64_t)sz.QuadPart;
    *cookie = m;
    return p;
}

void ec_os_unmap(const unsigned char *p, uint64_t size, void *cookie)
{
    (void)size;
    UnmapViewOfFile(p);
    CloseHandle((HANDLE)cookie);
}

void ec_os_lock(FILE *f)
{
    OVERLAPPED o = {0};
    LockFileEx((HANDLE)_get_osfhandle(_fileno(f)), LOCKFILE_EXCLUSIVE_LOCK, 0,
               MAXDWORD, MAXDWORD, &o);
}

int ec_os_fsync(FILE *f) { return fflush(f) || _commit(_fileno(f)) ? -1 : 0; }

/* ---------- drive discovery ---------- */

static const char *classify(STORAGE_BUS_TYPE bus, int seek)
{
    if (bus == BusTypeNvme) return "NVMe SSD";
    if (bus == BusTypeSd || bus == BusTypeMmc) return "SD/eMMC";
    if (bus == BusTypeVirtual || bus == BusTypeFileBackedVirtual) return "Virtual disk";
    if (seek < 0) return "Unknown";
    if (bus == BusTypeUsb) return seek ? "USB HDD" : "USB flash/SSD";
    return seek ? "HDD" : "SATA/SAS SSD";
}

static const char *advice(const char *type)
{
    if (!strcmp(type, "HDD") || !strcmp(type, "USB HDD"))
        return "Clear: Clear-Disk, then erasecure wipe (1 pass). Purge: ATA Secure Erase "
               "(drive maker's tool) or degauss.";
    if (!strcmp(type, "NVMe SSD") || !strcmp(type, "SATA/SAS SSD"))
        return "Purge: the drive maker's Sanitize / Secure Erase tool, or boot a Linux "
               "USB and use nvme sanitize / ATA Secure Erase. Overwrite is not Purge.";
    if (!strcmp(type, "Virtual disk"))
        return "Physical media is not reachable from a VM: use the provider's "
               "cryptographic erase / volume deletion for Purge.";
    if (!strcmp(type, "Unknown"))
        return "Could not tell HDD from SSD: treat as flash (overwrite = Clear only).";
    return "No reliable Purge command for most cards/sticks: overwrite is "
           "Clear at best; Destroy for moderate/high data.";
}

static void trim_copy(char *dst, size_t n, const char *base, DWORD off)
{
    dst[0] = 0;
    if (!off) return;
    const char *s = base + off;
    while (*s == ' ') s++;
    snprintf(dst, n, "%s", s);
    size_t l = strlen(dst);
    while (l && dst[l - 1] == ' ') dst[--l] = 0;
}

int ec_os_list_devices(void)
{
    printf("%-20s %-14s %10s  %-24s %s\n", "DRIVE", "TYPE", "SIZE", "MODEL", "IN USE");
    int shown = 0;
    for (int n = 0; n < 64; n++) {
        char path[32];
        snprintf(path, sizeof path, "\\\\.\\PhysicalDrive%d", n);
        HANDLE h = CreateFileA(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE)
            continue;
        STORAGE_PROPERTY_QUERY q = {StorageDeviceProperty, PropertyStandardQuery, {0}};
        union { STORAGE_DEVICE_DESCRIPTOR d; char buf[1024]; } u;
        DEVICE_SEEK_PENALTY_DESCRIPTOR sp;
        DISK_GEOMETRY_EX g;
        DWORD got;
        char vendor[64] = "", product[64] = "", model[130];
        STORAGE_BUS_TYPE bus = BusTypeUnknown;
        int seek = -1;
        memset(&u, 0, sizeof u);
        if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, &u, sizeof u,
                            &got, NULL)) {
            bus = u.d.BusType;
            trim_copy(vendor, sizeof vendor, u.buf, u.d.VendorIdOffset);
            trim_copy(product, sizeof product, u.buf, u.d.ProductIdOffset);
        }
        q.PropertyId = StorageDeviceSeekPenaltyProperty;
        if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, &sp, sizeof sp,
                            &got, NULL))
            seek = sp.IncursSeekPenalty ? 1 : 0;
        double gb = DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &g, sizeof g,
                                    &got, NULL) ? (double)g.DiskSize.QuadPart / 1e9 : 0;
        CloseHandle(h);
        snprintf(model, sizeof model, "%s%s%s", vendor, *vendor ? " " : "", product);
        const char *type = classify(bus, seek);
        int used = disk_has_volumes(n);
        printf("%-20s %-14s %8.1fGB  %-24.24s %s\n", path, type, gb, *model ? model : "-",
               used > 0 ? "yes" : used == 0 ? "no" : "?");
        printf("                     -> %s\n", advice(type));
        shown++;
    }
    if (!shown)
        puts("(no drives visible)");
    return 0;
}

/* ---------- shredding ---------- */

const char *ec_fs_warning(const char *path)
{
    wchar_t root[MAX_PATH], fsw[32];
    char fs[32];
    wchar_t *w = wide(path);
    BOOL ok = w && GetVolumePathNameW(w, root, MAX_PATH) &&
              GetVolumeInformationW(root, NULL, 0, NULL, NULL, NULL, fsw, 32);
    free(w);
    if (!ok)
        return NULL;
    utf8(fsw, fs, sizeof fs);
    if (!_stricmp(fs, "ReFS"))
        return "ReFS can block-clone and relocate data: old copies may survive an overwrite";
    if (!_stricmp(fs, "NTFS"))
        return "NTFS: Shadow Copies / System Restore / OneDrive versions may keep older "
               "copies; alternate data streams are not overwritten";
    return NULL;
}

int ec_shred_file(const char *path, int verify, uint64_t *bytes, char err[EC_ERRLEN])
{
    *bytes = 0;
    DWORD a = attrs(path);
    if (a == INVALID_FILE_ATTRIBUTES) {
        winerr(err, path);
        return -1;
    }
    if (a & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) {
        snprintf(err, EC_ERRLEN, "%s is not a regular file", path);
        return -1;
    }
    if (a & FILE_ATTRIBUTE_READONLY)
        set_attrs(path, a & ~(DWORD)FILE_ATTRIBUTE_READONLY);
    HANDLE h = open_u(path, GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING,
                      FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH);
    BY_HANDLE_FILE_INFORMATION fi;
    if (h == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(h, &fi)) {
        winerr(err, path);
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        return -1;
    }
    if (fi.nNumberOfLinks > 1) {
        snprintf(err, EC_ERRLEN, "%s has %lu hard links; content is shared, skipping",
                 path, (unsigned long)fi.nNumberOfLinks);
        CloseHandle(h);
        return -1;
    }
    uint64_t size = (uint64_t)fi.nFileSizeHigh << 32 | fi.nFileSizeLow;
    ec_target t = {.h = (intptr_t)h, .size = size, .sector = 512};
    LARGE_INTEGER zero = {0};
    if (size && ec_overwrite(&t, size, EC_RANDOM, verify, err)) {
        CloseHandle(h);
        return -1;
    }
    if (!SetFilePointerEx(h, zero, NULL, FILE_BEGIN) || !SetEndOfFile(h) ||
        !FlushFileBuffers(h)) {
        winerr(err, "truncate");
        CloseHandle(h);
        return -1;
    }
    CloseHandle(h);

    /* Rename to a random name in the same folder, then delete. */
    char tmp[MAX_PATH * 4];
    unsigned char rnd[8];
    const char *s1 = strrchr(path, '\\'), *s2 = strrchr(path, '/');
    const char *slash = s1 > s2 ? s1 : s2;
    int dl = slash ? (int)(slash - path + 1) : 0;
    if (ec_random(rnd, sizeof rnd)) {
        snprintf(err, EC_ERRLEN, "random generator failed");
        return -1;
    }
    int n = snprintf(tmp, sizeof tmp, "%.*s", dl, path);
    for (int i = 0; i < 8; i++)
        n += snprintf(tmp + n, sizeof tmp - (size_t)n, "%02x", rnd[i]);
    const char *victim = move_u(path, tmp) ? tmp : path;
    if (!delete_u(victim)) {
        winerr(err, victim);
        return -1;
    }
    *bytes = size;
    return 0;
}

/* Depth-first. Reparse points (symlinks, junctions, mounted folders) are
 * removed as links and never followed. */
static void walk(const char *dir, int verify, ec_shred_stats *st)
{
    char pat[MAX_PATH * 4], full[MAX_PATH * 4], nm[MAX_PATH * 4], err[EC_ERRLEN];
    WIN32_FIND_DATAW fd;
    snprintf(pat, sizeof pat, "%s\\*", dir);
    wchar_t *wp = wide(pat);
    HANDLE f = wp ? FindFirstFileW(wp, &fd) : INVALID_HANDLE_VALUE;
    free(wp);
    if (f != INVALID_HANDLE_VALUE) {
        do {
            utf8(fd.cFileName, nm, sizeof nm);
            if (!strcmp(nm, ".") || !strcmp(nm, ".."))
                continue;
            snprintf(full, sizeof full, "%s\\%s", dir, nm);
            DWORD a = fd.dwFileAttributes;
            if (a & FILE_ATTRIBUTE_READONLY)
                set_attrs(full, a & ~(DWORD)FILE_ATTRIBUTE_READONLY);
            if (a & FILE_ATTRIBUTE_REPARSE_POINT) {
                if ((a & FILE_ATTRIBUTE_DIRECTORY) ? rmdir_u(full) : delete_u(full))
                    st->links++;
                else
                    st->failed++;
            } else if (a & FILE_ATTRIBUTE_DIRECTORY) {
                walk(full, verify, st);
            } else {
                uint64_t b;
                if (ec_shred_file(full, verify, &b, err) == 0) {
                    st->files++;
                    st->bytes += b;
                } else {
                    fprintf(stderr, "  ! %s\n", err);
                    st->failed++;
                }
            }
        } while (FindNextFileW(f, &fd));
        FindClose(f);
    }
    if (rmdir_u(dir)) {
        st->dirs++;
    } else {
        winerr(err, dir);
        fprintf(stderr, "  ! %s\n", err);
        st->failed++;
    }
}

int ec_shred_tree(const char *path, int verify, ec_shred_stats *st)
{
    memset(st, 0, sizeof *st);
    walk(path, verify, st);
    return st->failed ? -1 : 0;
}
