/* audit.c - append-only, tamper-evident audit log.
 * SPDX-License-Identifier: MIT
 *
 * Each line is a JSON object. Its "hash" is SHA-256 over the line's text up
 * to (not including) the ,"hash" field, and that text includes "prev": the
 * previous line's hash. Editing, reordering or deleting any line breaks the
 * chain from that point on. Truncating the *tail* is only detectable if you
 * keep the latest hash somewhere else (e.g. print it in the report). */
#include "erasecure.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define GENESIS "0000000000000000000000000000000000000000000000000000000000000000"
#define MAXLINE 65536

/* Append s to out as a JSON string; out has room for 6*strlen(s)+3. */
static char *json_str(char *out, const char *s)
{
    *out++ = '"';
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { *out++ = '\\'; *out++ = (char)c; }
        else if (c < 0x20) out += sprintf(out, "\\u%04x", c);
        else *out++ = (char)c;
    }
    *out++ = '"';
    *out = 0;
    return out;
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
    size_t room = 512 + 6 * (strlen(action) + strlen(target) + strlen(result));
    char *line = malloc(MAXLINE), *body = malloc(room);
    FILE *f = ec_os_fopen(log, "a+b");
    int rc = -1;
    if (!line || !body || !f || room > MAXLINE)
        goto out;
    ec_os_lock(f);

    char prev[65] = GENESIS;
    long seq = 0;
    rewind(f);
    while (fgets(line, MAXLINE, f))
        if (field_hex(line, ",\"hash\":\"", prev) == 0)
            seq++;

    char ts[32];
    time_t now = time(NULL);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    char *p = body + sprintf(body, "{\"seq\":%ld,\"time\":\"%s\",\"tool\":\"erasecure "
                             EC_VERSION "\",\"action\":", seq + 1, ts);
    p = json_str(p, action);
    p += sprintf(p, ",\"target\":");
    p = json_str(p, target);
    p += sprintf(p, ",\"result\":");
    p = json_str(p, result);
    p += sprintf(p, ",\"bytes\":%llu,\"prev\":\"%s\"", (unsigned long long)bytes, prev);

    char h[65];
    if (ec_sha256_hex(body, (size_t)(p - body), h))
        goto out;
    fseek(f, 0, SEEK_END);
    if (fprintf(f, "%s,\"hash\":\"%s\"}\n", body, h) > 0 && ec_os_fsync(f) == 0)
        rc = 0;
out:
    if (f) fclose(f);
    free(line);
    free(body);
    return rc;
}

int ec_audit_verify(const char *log, long *bad_line)
{
    FILE *f = ec_os_fopen(log, "rb");
    char *line = malloc(MAXLINE);
    if (!f || !line) {
        if (f) fclose(f);
        free(line);
        return -1;
    }
    char expect_prev[65] = GENESIS, prev[65], h[65], calc[65];
    long n = 0;
    int rc = 0;
    while (fgets(line, MAXLINE, f)) {
        n++;
        char *hp = strstr(line, ",\"hash\":\"");
        if (!hp || field_hex(line, ",\"prev\":\"", prev) ||
            field_hex(hp, ",\"hash\":\"", h) ||
            ec_sha256_hex(line, (size_t)(hp - line), calc) ||
            strcmp(prev, expect_prev) || strcmp(calc, h)) {
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
