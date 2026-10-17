/* audit.c - append-only, tamper-evident audit log.
 * SPDX-License-Identifier: MIT
 *
 * Each line is a JSON object. Its "hash" is SHA-256 over the line's text up
 * to (not including) the ,"hash" field, and that text includes "prev": the
 * previous line's hash. Editing, reordering or deleting any line breaks the
 * chain from that point on. Truncating the *tail* is only detectable if you
 * keep the latest hash somewhere else (e.g. print it in the report). */
#define _GNU_SOURCE
#include "erasecure.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>

#define GENESIS "0000000000000000000000000000000000000000000000000000000000000000"

static void sha256_hex(const char *s, size_t n, char out[65])
{
    unsigned char md[32];
    unsigned len = 0;
    EVP_Digest(s, n, md, &len, EVP_sha256(), NULL);
    for (int i = 0; i < 32; i++)
        sprintf(out + 2 * i, "%02x", md[i]);
}

static void json_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') fprintf(f, "\\%c", c);
        else if (c < 0x20) fprintf(f, "\\u%04x", c);
        else fputc(c, f);
    }
    fputc('"', f);
}

/* Pull a 64-hex field value out of a line. */
static int field_hex(const char *line, const char *key, char out[65])
{
    const char *p = strstr(line, key);
    if (!p)
        return -1;
    p += strlen(key);
    if (strspn(p, "0123456789abcdef") < 64)
        return -1;
    memcpy(out, p, 64);
    out[64] = 0;
    return 0;
}

int ec_audit_append(const char *log, const char *action, const char *target,
                    const char *result, uint64_t bytes)
{
    FILE *f = fopen(log, "a+");
    if (!f)
        return -1;
    flock(fileno(f), LOCK_EX);

    char prev[65] = GENESIS, *line = NULL;
    size_t cap = 0;
    long seq = 0;
    rewind(f);
    while (getline(&line, &cap, f) > 0) {
        if (field_hex(line, ",\"hash\":\"", prev) == 0)
            seq++;
    }
    free(line);

    char ts[32];
    time_t now = time(NULL);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    char *body = NULL;
    size_t blen = 0;
    FILE *m = open_memstream(&body, &blen);
    if (!m) {
        fclose(f);
        return -1;
    }
    fprintf(m, "{\"seq\":%ld,\"time\":\"%s\",\"tool\":\"erasecure " EC_VERSION "\",\"action\":",
            seq + 1, ts);
    json_str(m, action);
    fputs(",\"target\":", m);
    json_str(m, target);
    fputs(",\"result\":", m);
    json_str(m, result);
    fprintf(m, ",\"bytes\":%llu,\"prev\":\"%s\"", (unsigned long long)bytes, prev);
    fclose(m);

    char h[65];
    sha256_hex(body, blen, h);
    fseek(f, 0, SEEK_END);
    int rc = fprintf(f, "%s,\"hash\":\"%s\"}\n", body, h) < 0 || fflush(f) ? -1 : 0;
    fsync(fileno(f));
    free(body);
    fclose(f);
    return rc;
}

int ec_audit_verify(const char *log, long *bad_line)
{
    FILE *f = fopen(log, "r");
    if (!f)
        return -1;
    char expect_prev[65] = GENESIS, prev[65], h[65], calc[65], *line = NULL;
    size_t cap = 0;
    long n = 0;
    int rc = 0;
    while (getline(&line, &cap, f) > 0) {
        n++;
        char *hp = strstr(line, ",\"hash\":\"");
        if (!hp || field_hex(line, ",\"prev\":\"", prev) ||
            field_hex(hp, ",\"hash\":\"", h)) {
            rc = 1;
            break;
        }
        sha256_hex(line, (size_t)(hp - line), calc);
        if (strcmp(prev, expect_prev) || strcmp(calc, h)) {
            rc = 1;
            break;
        }
        memcpy(expect_prev, h, sizeof h);
    }
    free(line);
    fclose(f);
    *bad_line = rc ? n : 0;
    return rc;
}
