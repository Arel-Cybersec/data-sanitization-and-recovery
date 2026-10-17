/* devices.c - list block devices and recommend a sanitization method.
 * SPDX-License-Identifier: MIT
 *
 * Guidance follows NIST SP 800-88 Rev. 2 (Sept 2025): Clear / Purge /
 * Destroy chosen by data sensitivity; one overwrite pass is enough for Clear
 * where overwrite is supported; flash media need device-native sanitize for
 * Purge. EraseCure performs Clear; Purge commands are printed, not run. */
#define _GNU_SOURCE
#include "erasecure.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_line(const char *dev, const char *attr, char *out, size_t n)
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

int ec_list_devices(void)
{
    DIR *d = opendir("/sys/block");
    if (!d) {
        perror("/sys/block");
        return -1;
    }
    printf("%-10s %-14s %10s  %-24s %s\n", "DEVICE", "TYPE", "SIZE", "MODEL",
           "MOUNTED");
    struct dirent *e;
    int n = 0;
    while ((e = readdir(d))) {
        const char *nm = e->d_name;
        if (nm[0] == '.' || !strncmp(nm, "loop", 4) || !strncmp(nm, "ram", 3) ||
            !strncmp(nm, "zram", 4) || !strncmp(nm, "dm-", 3) ||
            !strncmp(nm, "md", 2) || !strncmp(nm, "sr", 2))
            continue;
        char rot[8] = "0", size[32] = "0", model[64] = "-", p[PATH_MAX],
             real[PATH_MAX];
        read_line(nm, "queue/rotational", rot, sizeof rot);
        read_line(nm, "size", size, sizeof size);
        read_line(nm, "device/model", model, sizeof model);
        snprintf(p, sizeof p, "/sys/block/%s", nm);
        int usb = realpath(p, real) && strstr(real, "/usb");
        const char *type = ec_classify(nm, rot[0] == '1', usb);
        double gb = strtod(size, NULL) * 512.0 / 1e9; /* sysfs size is 512-byte units */
        printf("/dev/%-5s %-14s %8.1fGB  %-24.24s %s\n", nm, type, gb, model,
               ec_device_is_mounted(nm) ? "yes" : "no");
        printf("           -> %s\n", advice(type));
        n++;
    }
    closedir(d);
    if (!n)
        puts("(no physical block devices visible)");
    return 0;
}
