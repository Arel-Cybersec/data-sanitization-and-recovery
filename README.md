# Data Sanitization and Recovery — EraseCure 2

A small, tested Linux command-line tool for **erasing** data and **recovering** deleted files, aligned with
**NIST SP 800-88 Rev. 2** (*Guidelines for Media Sanitization*, September 2025, which supersedes Rev. 1).

A ground-up rewrite inspired by [EraseCure / DataSanitization_SIH26](https://github.com/AbdullahShaikh4226/DataSanitization_SIH26).
It does less, and everything it does builds cleanly with `-Werror` and is covered by tests.

| Command | What it does |
|---|---|
| `erasecure devices` | Lists drives (HDD, SATA SSD, NVMe, USB, SD/eMMC, virtual) and the right Clear/Purge method for each |
| `erasecure wipe <file\|/dev/X>` | Overwrites the whole target, then reads it back to verify every byte |
| `erasecure shred <file\|folder>` | Overwrites, renames and deletes files; folders recursively, symlinks never followed |
| `erasecure image <drive> <out.img>` | Copies a drive or USB stick read-only into an image file, skipping bad sectors, with a SHA-256 hash |
| `erasecure carve <image> <outdir>` | Recovers JPEG, PNG, GIF, PDF and ZIP (incl. DOCX/XLSX/PPTX) from a raw disk image |
| `erasecure audit-verify` | Checks the tamper-evident SHA-256 hash-chained audit log |

## Build

```bash
sudo apt-get install -y build-essential cmake libssl-dev
cmake -B build && cmake --build build
ctest --test-dir build --output-on-failure        # all tests run on temp files only
cmake -B build-asan -DSANITIZE=ON -DCMAKE_BUILD_TYPE=Debug   # optional ASan/UBSan build
```

## Usage

```bash
./build/erasecure devices
./build/erasecure wipe old-backup.img                 # 1 pass of zeros, verified
./build/erasecure wipe /dev/sdX --confirm /dev/sdX    # whole drive; refuses if anything on it is mounted
./build/erasecure shred ./secrets/
sudo ./build/erasecure image /dev/sdX evidence.img  # 1. copy the drive (read-only)
./build/erasecure carve evidence.img recovered/      # 2. recover deleted files from the copy
./build/erasecure audit-verify
```

Every action is appended to `erasecure-audit.jsonl` (change with `--log FILE`). Each line stores the SHA-256 of
the previous line, so editing, reordering or deleting a line is detected. Deleting the newest lines is only detectable
if you keep the last hash elsewhere.

## What changed from the original

- **It builds and its tests pass.** The original did not compile on Linux: missing `_POSIX_C_SOURCE`/`_GNU_SOURCE`,
  undeclared `folder_erase_recursive`, unknown `dev_t`/`ino_t`. None of its 7 test suites could run.
- **Rev. 2 guidance.** Defaults to **one pass**, as NIST SP 800-88 Rev. 2 says multi-pass and DoD 5220.22-M style
  overwrites are unnecessary on modern media. Extra passes are allowed but warned about.
- **Real verification.** Random data is an AES-256-CTR keystream under a fresh key, so it can be regenerated and
  every byte compared after writing, not just sampled.
- **Safety on real drives.** Block devices need `--confirm <same path>`. They are opened `O_EXCL` and refused
  if the disk or any of its partitions is mounted or used as swap.
- **Honest limits.** Overwriting an SSD or flash drive is *Clear*, not *Purge*. `devices` prints the device's
  own purge command instead: `nvme sanitize`, ATA Secure Erase, or the cloud provider's crypto-erase.
- **Structure-aware carving.** Walks JPEG markers, PNG chunks and ZIP end-of-central-directory records instead of
  cutting at the first footer, so thumbnails embedded in JPEGs don't truncate the photo.
- **Smaller.** About 1,150 lines including tests, instead of about 12,000, with no SQLite dependency.

## Know the limits (read before trusting it with real data)

- **SSDs, USB sticks, SD cards:** wear levelling and spare blocks mean an overwrite cannot reach every cell.
  For **Purge**, use the drive's own sanitize command (see `erasecure devices`). NIST Rev. 2 also requires
  validated cryptography and key zeroization before counting cryptographic erase as Purge.
- **`shred` on files** only reaches blocks the filesystem currently maps to that file. Copy-on-write filesystems
  (btrfs, ZFS), snapshots, journals, backups and SSDs can keep old copies; the tool warns on btrfs, ZFS, XFS and tmpfs.
  To remove a file reliably, sanitize the whole device.
- **Carving** recovers contiguous files only. Fragmented files come back incomplete or not at all.
- **Physical destruction:** IEEE 2883 (referenced by NIST Rev. 2) does not approve shredding or pulverizing for
  modern HDDs and SSDs as a destruct method on its own; follow that standard.
- This tool is a Clear-level overwriter plus guidance. It is **not** a certified sanitization product.

## References

- NIST SP 800-88 Rev. 2: https://csrc.nist.gov/pubs/sp/800/88/r2/final
- NIST SP 800-88 Rev. 2 FAQ: https://csrc.nist.gov/files/pubs/sp/800/88/r2/final/docs/sp800-88r2-faq.pdf
- `nvme-sanitize(1)`: https://manpages.debian.org/experimental/nvme-cli/nvme-sanitize.1.en.html
- `nvme-sanitize-log(1)`: https://manpages.debian.org/trixie/nvme-cli/nvme-sanitize-log.1.en.html
- `hdparm(8)`: https://manpages.debian.org/trixie/hdparm/hdparm.8.en.html

## License

MIT. See [LICENSE](LICENSE). Erasing data is irreversible; you use this tool at your own risk.
