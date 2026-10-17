/* main.c - EraseCure 2 command line.
 * SPDX-License-Identifier: MIT */
#include "erasecure.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#define DRIVE "\\\\.\\PhysicalDriveN"
#else
#define DRIVE "/dev/sdX"
#endif

static const char *audit_log = "erasecure-audit.jsonl";

static int usage(void)
{
    fputs(
        "EraseCure " EC_VERSION " - data sanitization and recovery\n\n"
        "usage:\n"
        "  erasecure devices\n"
        "      list drives with a NIST SP 800-88 Rev. 2 method recommendation\n"
        "  erasecure wipe <file|" DRIVE "> [--random] [--passes N] [--no-verify]\n"
        "                 [--confirm " DRIVE "]\n"
        "      overwrite the whole target (default: 1 pass of zeros, verified)\n"
        "  erasecure shred <file|folder> [--no-verify]\n"
        "      overwrite, rename and delete files (folders recursively)\n"
        "  erasecure image <drive|file> <out.img>\n"
        "      copy a drive read-only into an image (bad sectors zero-filled), with SHA-256\n"
        "  erasecure carve <image> <outdir> [--max-mb N]\n"
        "      recover JPEG/PNG/GIF/PDF/ZIP(+DOCX/XLSX) files from a raw image\n"
        "  erasecure audit-verify\n"
        "      check the tamper-evident audit log\n\n"
        "options:  --log FILE   audit log path (default erasecure-audit.jsonl)\n",
        stderr);
    return 2;
}

static void audit(const char *action, const char *target, const char *res,
                  uint64_t bytes)
{
    if (ec_audit_append(audit_log, action, target, res, bytes))
        fprintf(stderr, "warning: could not write audit log %s\n", audit_log);
}

int main(int argc, char **argv)
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8); /* we print UTF-8 */
    char **u8 = ec_os_utf8_args(&argc);
    if (u8)
        argv = u8;
#endif
    const char *pos[3] = {0}, *confirm = NULL;
    int npos = 0, verify = 1, passes = 1;
    enum ec_pattern pat = EC_ZERO;
    unsigned long long max_mb = 256;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int more = i + 1 < argc;
        if (!strcmp(a, "--random")) pat = EC_RANDOM;
        else if (!strcmp(a, "--no-verify")) verify = 0;
        else if (!strcmp(a, "--passes") && more) passes = atoi(argv[++i]);
        else if (!strcmp(a, "--confirm") && more) confirm = argv[++i];
        else if (!strcmp(a, "--max-mb") && more) max_mb = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--log") && more) audit_log = argv[++i];
        else if (!strcmp(a, "--version")) { puts(EC_VERSION); return 0; }
        else if (a[0] == '-' || npos == 3) return usage();
        else pos[npos++] = a;
    }
    if (!npos)
        return usage();
    const char *cmd = pos[0];

    if (!strcmp(cmd, "devices") && npos == 1)
        return ec_os_list_devices() ? 1 : 0;

    if (!strcmp(cmd, "wipe") && npos == 2) {
        if (passes < 1 || passes > 35) {
            fputs("--passes must be 1..35\n", stderr);
            return 2;
        }
        if (passes > 1)
            fputs("note: NIST SP 800-88 Rev. 2 considers one pass sufficient; "
                  "extra passes only add wear and time.\n", stderr);
        ec_wipe_result r;
        int rc = ec_wipe_path(pos[1], pat, passes, verify, confirm, &r);
        if (rc) {
            fprintf(stderr, "wipe failed: %s\n", r.err);
            audit("wipe", pos[1], r.err, r.bytes);
            return 1;
        }
        printf("wiped %s: %llu bytes, %d pass(es) of %s, %s\n", pos[1],
               (unsigned long long)r.bytes, r.passes,
               pat == EC_RANDOM ? "random" : "zeros",
               r.verified ? "verified" : "NOT verified");
        if (r.is_device)
            puts("reminder: on SSD/flash an overwrite is Clear, not Purge "
                 "(spare/remapped blocks are unreachable). See `erasecure devices`.");
        audit("wipe", pos[1], r.verified ? "ok-verified" : "ok", r.bytes);
        return 0;
    }

    if (!strcmp(cmd, "shred") && npos == 2) {
        const char *w = ec_fs_warning(pos[1]);
        if (w)
            fprintf(stderr, "warning: %s\n", w);
        int isdir = ec_os_is_dir(pos[1]);
        if (isdir < 0) {
            perror(pos[1]);
            return 1;
        }
        if (isdir) {
            ec_shred_stats s;
            int rc = ec_shred_tree(pos[1], verify, &s);
            printf("shredded %u file(s), %llu bytes; removed %u folder(s), "
                   "%u link(s); %u failure(s)\n", s.files,
                   (unsigned long long)s.bytes, s.dirs, s.links, s.failed);
            audit("shred-folder", pos[1], rc ? "partial" : "ok", s.bytes);
            return rc ? 1 : 0;
        }
        char err[EC_ERRLEN];
        uint64_t bytes;
        if (ec_shred_file(pos[1], verify, &bytes, err)) {
            fprintf(stderr, "shred failed: %s\n", err);
            audit("shred", pos[1], err, 0);
            return 1;
        }
        printf("shredded %s (%llu bytes)\n", pos[1], (unsigned long long)bytes);
        audit("shred", pos[1], verify ? "ok-verified" : "ok", bytes);
        return 0;
    }

    if (!strcmp(cmd, "image") && npos == 3) {
        ec_image_result r;
        if (ec_image(pos[1], pos[2], &r)) {
            fprintf(stderr, "image failed: %s\n", r.err);
            audit("image", pos[1], r.err, 0);
            return 1;
        }
        printf("imaged %s -> %s: %llu bytes, %llu unreadable sector(s)\nsha256 %s\n",
               pos[1], pos[2], (unsigned long long)r.bytes,
               (unsigned long long)r.bad_sectors, r.sha256);
        audit("image", pos[1], r.sha256, r.bytes);
        return 0;
    }

    if (!strcmp(cmd, "carve") && npos == 3) {
        ec_carve_stats s;
        int rc = ec_carve(pos[1], pos[2], max_mb << 20, &s);
        if (rc && !s.found) {
            perror("carve");
            return 1;
        }
        printf("recovered %u file(s) into %s:", s.found, pos[2]);
        for (int i = 0; ec_carve_type_name(i); i++)
            if (s.by_type[i])
                printf(" %s=%u", ec_carve_type_name(i), s.by_type[i]);
        putchar('\n');
        audit("carve", pos[1], rc ? "partial" : "ok", s.found);
        return rc ? 1 : 0;
    }

    if (!strcmp(cmd, "audit-verify") && npos == 1) {
        long bad;
        int rc = ec_audit_verify(audit_log, &bad);
        if (rc < 0) {
            perror(audit_log);
            return 1;
        }
        if (rc) {
            printf("TAMPERED: chain breaks at line %ld of %s\n", bad, audit_log);
            return 1;
        }
        printf("audit log %s: chain intact\n", audit_log);
        return 0;
    }
    return usage();
}
