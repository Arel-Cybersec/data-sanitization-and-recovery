/* Self-contained tests. Everything runs on temp files; no device is touched.
 * SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#undef NDEBUG
#include "../src/erasecure.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char dir[] = "/tmp/erasecure-test-XXXXXX";

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

    assert(ec_wipe_path("/dev/null", EC_ZERO, 1, 0, NULL, &r) != 0);   /* char dev */
    assert(ec_wipe_path(path("missing"), EC_ZERO, 1, 0, NULL, &r) != 0);
    assert(ec_device_is_mounted("no-such-device-xyz") == 0);
    puts("ok wipe");
}

static void test_shred(void)
{
    char err[EC_ERRLEN];
    put(path("s.txt"), "secret secret", 13);
    assert(ec_shred_file(path("s.txt"), 1, err) == 0);
    assert(access(path("s.txt"), F_OK) != 0);

    put(path("h1"), "x", 1);
    assert(link(path("h1"), path("h2")) == 0);
    assert(ec_shred_file(path("h1"), 1, err) != 0); /* hard links refused */
    unlink(path("h1")); unlink(path("h2"));

    mkdir(path("tree"), 0700);
    mkdir(path("tree/sub"), 0700);
    put(path("tree/a"), "aaaa", 4);
    put(path("tree/sub/b"), "", 0);
    put(path("outside"), "keep", 4);
    assert(symlink(path("outside"), path("tree/link")) == 0);
    ec_shred_stats st;
    assert(ec_shred_tree(path("tree"), 1, &st) == 0);
    assert(st.files == 2 && st.dirs == 2 && st.links == 1 && st.bytes == 4);
    assert(access(path("tree"), F_OK) != 0);
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
    unsigned char *p = memmem(buf, n, "\"bytes\":20", 10);
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
}

int main(void)
{
    assert(mkdtemp(dir));
    assert(!strcmp(ec_classify("nvme0n1", 0, 0), "NVMe SSD"));
    assert(!strcmp(ec_classify("sda", 1, 0), "HDD"));
    assert(!strcmp(ec_classify("sdb", 0, 1), "USB flash/SSD"));
    assert(!strcmp(ec_classify("mmcblk0", 0, 0), "SD/eMMC"));
    assert(!strcmp(ec_classify("vda", 1, 0), "Virtual disk"));
    test_wipe();
    test_shred();
    test_audit();
    test_carve();
    char cmd[600];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    assert(system(cmd) == 0);
    puts("all tests passed");
    return 0;
}
