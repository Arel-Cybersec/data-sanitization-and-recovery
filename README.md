# Data Sanitization and Recovery — EraseCure 2

A small, tested command-line tool for **Windows (PowerShell)** and **Linux** for **erasing** data and **recovering** deleted files, aligned with
**NIST SP 800-88 Rev. 2** (*Guidelines for Media Sanitization*, September 2025, which supersedes Rev. 1).

A ground-up rewrite inspired by [EraseCure / DataSanitization_SIH26](https://github.com/AbdullahShaikh4226/DataSanitization_SIH26).
It does less, and everything it does builds cleanly with `-Werror` and is covered by tests.

| Command | What it does |
|---|---|
| `erasecure devices` | Lists drives (HDD, SATA SSD, NVMe, USB, SD/eMMC, virtual) and the right Clear/Purge method for each |
| `erasecure wipe <file\|drive>` | Overwrites the whole target, then reads it back to verify every byte |
| `erasecure shred <file\|folder>` | Overwrites, renames and deletes files; folders recursively, symlinks never followed |
| `erasecure image <drive> <out.img>` | Copies a drive or USB stick read-only into an image file, skipping bad sectors, with a SHA-256 hash |
| `erasecure carve <image> <outdir>` | Recovers JPEG, PNG, GIF, PDF and ZIP (incl. DOCX/XLSX/PPTX) from a raw disk image |
| `erasecure audit-verify` | Checks the tamper-evident SHA-256 hash-chained audit log |

## Windows (PowerShell)

1. Download `erasecure.exe` from the [Releases page](https://github.com/Arel-Cybersec/data-sanitization-and-recovery/releases/latest).
   It is a single file with nothing to install; it uses only Windows' built-in crypto (CNG).
2. Optionally, check the download matches the published hash: `Get-FileHash .\erasecure.exe` and compare it with `erasecure.exe.sha256`.
3. Open PowerShell in the download folder and run:

```powershell
.\erasecure.exe devices                       # list drives + how to erase each (no admin needed)
.\erasecure.exe shred .\secret.docx           # erase one file
.\erasecure.exe shred .\OldFolder             # erase a folder
.\erasecure.exe carve .\disk.img .\recovered  # recover deleted files from an image
.\erasecure.exe audit-verify
```

Working with whole drives needs **PowerShell opened as Administrator**. Drives are named as in `Get-Disk`: disk 2 is `\\.\PhysicalDrive2`.

```powershell
.\erasecure.exe image \\.\PhysicalDrive2 E:\usb.img             # copy a drive read-only
.\erasecure.exe carve E:\usb.img E:\recovered                     # recover from the copy

Clear-Disk -Number 2 -RemoveData                                  # wipe refuses drives that still have partitions
.\erasecure.exe wipe \\.\PhysicalDrive2 --confirm \\.\PhysicalDrive2
```

For safety, `wipe` on Windows refuses any drive that still has a partition or volume, which always includes your
system disk. You have to remove the partitions deliberately first.

## Linux

### Build

```bash
sudo apt-get install -y build-essential cmake libssl-dev
cmake -B build && cmake --build build
ctest --test-dir build --output-on-failure        # all tests run on temp files only
cmake -B build-asan -DSANITIZE=ON -DCMAKE_BUILD_TYPE=Debug   # optional ASan/UBSan build
```

### Usage

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

## Building the Windows .exe yourself

GitHub Actions builds and tests it on every push; tagging `v*` publishes it to Releases. To build locally, use
MSYS2 UCRT64 (`pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake`), then `cmake -B build && cmake --build build`.

## What changed from the original

- **It builds and its tests pass.** The original did not compile on Linux: missing `_POSIX_C_SOURCE`/`_GNU_SOURCE`,
  undeclared `folder_erase_recursive`, unknown `dev_t`/`ino_t`. None of its 7 test suites could run.
- **Rev. 2 guidance.** Defaults to **one pass**, as NIST SP 800-88 Rev. 2 says multi-pass and DoD 5220.22-M style
  overwrites are unnecessary on modern media. Extra passes are allowed but warned about.
- **Real verification.** Random data is an AES-256-CTR keystream under a fresh key, so it can be regenerated and
  every byte compared after writing, not just sampled.
- **Safety on real drives.** Drives need `--confirm <same path>`. On Linux they are opened `O_EXCL` and refused
  if the disk or any partition is mounted or used as swap. On Windows they are refused while any volume exists on them.
- **Runs on Windows and Linux.** Same commands and the same tests on both; full Unicode file names on Windows.
- **Honest limits.** Overwriting an SSD or flash drive is *Clear*, not *Purge*. `devices` prints the device's
  own purge command instead: `nvme sanitize`, ATA Secure Erase, or the cloud provider's crypto-erase.
- **Structure-aware carving.** Walks JPEG markers, PNG chunks and ZIP end-of-central-directory records instead of
  cutting at the first footer, so thumbnails embedded in JPEGs don't truncate the photo.
- **Smaller.** About 2,100 lines for both platforms including tests, instead of about 12,000, with no SQLite dependency.

## Know the limits (read before trusting it with real data)

- **SSDs, USB sticks, SD cards:** wear levelling and spare blocks mean an overwrite cannot reach every cell.
  For **Purge**, use the drive's own sanitize command (see `erasecure devices`). NIST Rev. 2 also requires
  validated cryptography and key zeroization before counting cryptographic erase as Purge.
- **`shred` on files** only reaches blocks the filesystem currently maps to that file. Copy-on-write filesystems
  (btrfs, ZFS, ReFS), snapshots, Windows Shadow Copies / System Restore, OneDrive history, journals, backups and SSDs
  can keep old copies. NTFS alternate data streams are not overwritten. The tool warns about these.
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
- `Clear-Disk`: https://learn.microsoft.com/en-us/powershell/module/storage/clear-disk

## License

MIT. See [LICENSE](LICENSE). Erasing data is irreversible; you use this tool at your own risk.
