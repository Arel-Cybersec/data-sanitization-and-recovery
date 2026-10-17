/* Self-contained tests. Everything runs on temp files; no device is touched.
 * SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#undef NDEBUG
#include "../src/erasecure.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#define exists(p) (GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES)
#define hardlink(a, b) (CreateHardLinkA(b, a, NULL) ? 0 : -1)
#define remove_file(p) DeleteFileA(p)
#else
#include <sys/stat.h>
#include <unistd.h>
#define exists(p) (access(p, F_OK) == 0)
#define hardlink(a, b) link(a, b)
#define remove_file(p) unlink(p)
#endif

static char dir[512];

static char *path(const char *name)
{
    static char p[4][512];
    static int i;
    i = (i + 1) % 4;
    snprintf(p[i], sizeof p[i], "%s/%s", dir, name);
    return p[i];
}

static void put(const char *p, const void *d, size_t n)
{
    FILE *f = fopen(p, "wb");
    assert(f && fwrite(d, 1, n, f) == n && fclose(f) == 0);
}

static size_t get(const char *p, unsigned char *buf, size_t cap)
{
    FILE *f = fopen(p, "rb");
    assert(f);
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return n;
}

static void test_wipe(void)
{
    static unsigned char data[3 << 20 | 123], back[sizeof data];
    memset(data, 'A', sizeof data);
    put(path("w.img"), data, sizeof data);

    ec_wipe_result r;
    assert(ec_wipe_path(path("w.img"), EC_ZERO, 1, 1, NULL, &r) == 0);
    assert(r.bytes == sizeof data && r.passes == 1 && r.verified);
    assert(get(path("w.img"), back, sizeof back) == sizeof data);
    for (size_t i = 0; i < sizeof back; i++) assert(back[i] == 0);

    assert(ec_wipe_path(path("w.img"), EC_RANDOM, 2, 1, NULL, &r) == 0);
    assert(r.passes == 2 && r.verified);
    get(path("w.img"), back, sizeof back);
    size_t zeros = 0;
    for (size_t i = 0; i < sizeof back; i++) zeros += back[i] == 0;
    assert(zeros < sizeof back / 100); /* ~1/256 expected */

    assert(ec_wipe_path(path("missing"), EC_ZERO, 1, 0, NULL, &r) != 0);
    /* A drive is never opened for writing without --confirm. */
    assert(ec_wipe_path("\\\\.\\PhysicalDrive0", EC_ZERO, 1, 0, NULL, &r) != 0);
#ifndef _WIN32
    assert(ec_wipe_path("/dev/null", EC_ZERO, 1, 0, NULL, &r) != 0);   /* char dev */
    assert(ec_device_is_mounted("no-such-device-xyz") == 0);
#endif
    puts("ok wipe");
}

static void test_shred(void)
{
    char err[EC_ERRLEN];
    uint64_t sb;
    put(path("s.txt"), "secret secret", 13);
    assert(ec_shred_file(path("s.txt"), 1, &sb, err) == 0);
    assert(!exists(path("s.txt")) && sb == 13);

    put(path("h1"), "x", 1);
    assert(hardlink(path("h1"), path("h2")) == 0);
    assert(ec_shred_file(path("h1"), 1, &sb, err) != 0); /* hard links refused */
    remove_file(path("h1")); remove_file(path("h2"));

    assert(ec_os_mkdir(path("tree")) == 0);
    assert(ec_os_mkdir(path("tree/sub")) == 0);
    put(path("tree/a"), "aaaa", 4);
    put(path("tree/sub/b"), "", 0);
    put(path("outside"), "keep", 4);
#ifdef _WIN32
    unsigned links = 0; /* symlinks need admin/developer mode on Windows */
#else
    unsigned links = 1;
    assert(symlink(path("outside"), path("tree/link")) == 0);
#endif
    ec_shred_stats st;
    assert(ec_shred_tree(path("tree"), 1, &st) == 0);
    assert(st.files == 2 && st.dirs == 2 && st.links == links && st.bytes == 4);
    assert(!exists(path("tree")));
    unsigned char b[8];
    assert(get(path("outside"), b, sizeof b) == 4 && !memcmp(b, "keep", 4));
    puts("ok shred");
}

static void test_audit(void)
{
    const char *log = path("audit.jsonl");
    long bad;
    assert(ec_audit_append(log, "wipe", "/x \"quoted\"", "ok", 10) == 0);
    assert(ec_audit_append(log, "shred", "/y", "ok", 20) == 0);
    assert(ec_audit_append(log, "carve", "/z", "ok", 3) == 0);
    assert(ec_audit_verify(log, &bad) == 0);

    unsigned char buf[4096];
    size_t n = get(log, buf, sizeof buf);
    unsigned char *p = NULL;
    for (size_t i = 0; i + 10 <= n && !p; i++)
        if (!memcmp(buf + i, "\"bytes\":20", 10)) p = buf + i;
    assert(p);
    p[9] = '1'; /* 20 -> 21 */
    put(log, buf, n);
    assert(ec_audit_verify(log, &bad) == 1 && bad == 2);
    puts("ok audit");
}

static void test_carve(void)
{
    static const unsigned char jpg[] = {
        0xFF,0xD8, 0xFF,0xE0,0x00,0x07,'J','F','I','F',0,
        0xFF,0xDA,0x00,0x04,0x01,0x02,
        0x12,0xFF,0x00,0x34,0xFF,0xD0,0x56, 0xFF,0xD9};
    static const unsigned char png[] = {
        0x89,'P','N','G','\r','\n',0x1a,'\n',
        0,0,0,13,'I','H','D','R', 0,0,0,1,0,0,0,1,8,0,0,0,0, 1,2,3,4,
        0,0,0,0,'I','E','N','D', 0xAE,0x42,0x60,0x82};
    static const char pdf[] = "%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\nupdate\n%%EOF\n";
    static const unsigned char gif[] = {
        'G','I','F','8','9','a',1,0,1,0,0,0,0, ',',0,0,0,0,1,0,1,0,0, 2,2,0x44,1,0, 0x00,0x3B};
    static const unsigned char zip[] = {
        'P','K',3,4, 9,9,9,9, 'P','K',1,2, 7,7,
        'P','K',5,6, 0,0,0,0,1,0,1,0, 0,0,0,0, 0,0,0,0, 2,0, 'h','i'};
    static unsigned char img[1 << 16];
    struct { const void *d; size_t n; size_t at; } parts[] = {
        {jpg, sizeof jpg, 1000}, {png, sizeof png, 5000},
        {pdf, sizeof pdf - 1, 9000}, {gif, sizeof gif, 13000},
        {zip, sizeof zip, 17000}, {"\xFF\xD8\xFF", 3, 30000} /* false positive */};
    for (size_t i = 0; i < 6; i++) memcpy(img + parts[i].at, parts[i].d, parts[i].n);
    put(path("disk.img"), img, sizeof img);

    ec_carve_stats st;
    assert(ec_carve(path("disk.img"), path("out"), 1 << 20, &st) == 0);
    assert(st.found == 5);
    const char *names[] = {"0000000003e8.jpg", "000000001388.png", "000000002328.pdf",
                           "0000000032c8.gif", "000000004268.zip"};
    unsigned char back[256];
    for (int i = 0; i < 5; i++) {
        char n[64];
        snprintf(n, sizeof n, "out/%s", names[i]);
        assert(get(path(n), back, sizeof back) == parts[i].n);
        assert(!memcmp(back, parts[i].d, parts[i].n));
    }
    puts("ok carve");

    ec_image_result ir;
    assert(ec_image(path("disk.img"), path("copy.img"), &ir) == 0);
    assert(ir.bytes == sizeof img && ir.bad_sectors == 0 && strlen(ir.sha256) == 64);
    static unsigned char copy[sizeof img];
    assert(get(path("copy.img"), copy, sizeof copy) == sizeof img && !memcmp(copy, img, sizeof img));
    assert(ec_image(path("disk.img"), path("copy.img"), &ir) != 0); /* never overwrites */
    puts("ok image");
}

int main(void)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    assert(GetTempPathA(sizeof tmp, tmp));
    snprintf(dir, sizeof dir, "%serasecure-test-%lu", tmp, (unsigned long)GetCurrentProcessId());
    assert(ec_os_mkdir(dir) == 0);
#else
    snprintf(dir, sizeof dir, "/tmp/erasecure-test-XXXXXX");
    assert(mkdtemp(dir));
    assert(!strcmp(ec_classify("nvme0n1", 0, 0), "NVMe SSD"));
    assert(!strcmp(ec_classify("sda", 1, 0), "HDD"));
    assert(!strcmp(ec_classify("sdb", 0, 1), "USB flash/SSD"));
    assert(!strcmp(ec_classify("mmcblk0", 0, 0), "SD/eMMC"));
    assert(!strcmp(ec_classify("vda", 1, 0), "Virtual disk"));
#endif
    test_wipe();
    test_shred();
    test_audit();
    test_carve();
    ec_shred_stats st; /* clean up with our own folder shredder */
    assert(ec_shred_tree(dir, 0, &st) == 0 && !exists(dir));
    puts("all tests passed");
    return 0;
}
