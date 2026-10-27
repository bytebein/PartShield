<p align="center">
  <img src="assets/logo.svg" width="112" alt="">
</p>

<h1 align="center">PartShield</h1>

<p align="center">
  <strong>Backups that are restored and verified before they're called good.</strong>
</p>

<p align="center">
  <a href="https://partshield.io"><img src="https://img.shields.io/badge/web-partshield.io-1f7a57" alt="partshield.io"></a>
  <img src="https://img.shields.io/badge/Rust-1f7a57?logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/Debian_13-live_USB-1f7a57?logo=debian&logoColor=white" alt="Debian 13">
  <img src="https://img.shields.io/badge/Secure_Boot-yes-1f7a57" alt="Secure Boot">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-1f7a57" alt="GPL-3.0"></a>
  <a href="https://github.com/bytebein/PartShield/actions/workflows/ci.yml"><img src="https://github.com/bytebein/PartShield/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/status-in_development-9a5b00" alt="In development">
</p>

<p align="center">
  <strong>English</strong> · <a href="README.es.md">Español</a>
</p>

<p align="center">
  <img src="assets/capturas/inicio.png" width="720" alt="PartShield home screen">
</p>

<p align="center"><sub>The interface is in Spanish for now; English is on the <a href="ROADMAP.md">roadmap</a>.</sub></p>

---

## Why

A backup isn't done until it has been restored.

PartShield was born from a real bug: partclone copied Btrfs filesystems with
`BLOCK_GROUP_TREE` and reported success, but the copies wouldn't mount because
the `chunk_root` was never copied
([partclone#303](https://github.com/Thomas-Tsai/partclone/issues/303),
[rescuezilla#672](https://github.com/rescuezilla/rescuezilla/issues/672)).
Three "successful" backups that were useless.

So PartShield doesn't trust a copy just because it finished without errors.
It restores it somewhere else, mounts it, compares it with the original, and
only then tells you whether it's good.

## How to use it

Boot the PartShield USB (Debian 13 with Secure Boot, no desktop: just the app)
and back up in three steps.

| | |
| --- | --- |
| **1 · What** | The whole disk or only the partitions you want, with checkboxes. |
| **2 · Where** | Another disk, a USB drive for example. Nothing already on it is deleted. |
| **3 · Start** | One progress bar while it copies and verifies. |

<p align="center">
  <img src="assets/capturas/copia.png" width="720" alt="Choosing what to back up and where">
</p>

At the end you get one of three answers:

| | Result | Meaning |
| --- | --- | --- |
| 🟢 | **Verified** | Restored separately and identical to the original. Safe to restore. |
| 🟡 | **Not fully verified** | Nothing failed, but some step couldn't run. Check which before trusting it. |
| 🔴 | **Not valid** | Something failed. Don't trust this backup. |

<p align="center">
  <img src="assets/capturas/resultado.png" width="720" alt="Result: backup verified">
</p>

The **Advanced** switch shows everything else: superblock, features, which
backup modes are safe, subvolumes, and every command that runs.

## How it verifies

Every backup goes through five steps. It is **valid** only if all five pass.

| Step | Btrfs (`btrfs send`) | Everything else (sector by sector) |
| --- | --- | --- |
| **restore** | `btrfs receive` into a scratch Btrfs, each stream's hash checked first | The image is written to a scratch file |
| **structure** | `btrfs check --readonly` | The filesystem's own read-only fsck (ext4, vfat, exFAT, XFS, NTFS) |
| **mount** | Mounted read-only | Mounted read-only |
| **compare** | Scrub, and the same tree as the original: types, sizes, permissions, owners and links | Bit-for-bit identical to the device |
| **sample** | BLAKE3 of a sample of files against the original | 64 chunks re-read from the source and compared |

Every external command is shown before it runs and recorded in the report
(JSON and HTML, optionally signed with ed25519) saved next to the backup.

## Command line

The GUI and the CLI share the same engine.

```sh
cargo build --release
sudo target/release/partshield inspect /dev/nvme0n1p2

# Several subvolumes, plus partition table, ESP and UUID
sudo target/release/partshield backup --subvol @=/ --subvol @home=/home --layout \
    --dest /mnt/usb/backups --keep-snapshot

# Incremental on top of an earlier valid backup
sudo target/release/partshield backup /home --dest /mnt/usb/backups --keep-snapshot \
    --parent /mnt/usb/backups/home-YYYYMMDD-HHMMSS.report.json

# Sector-by-sector image of an unmounted partition
sudo target/release/partshield backup --mode raw /dev/sdb2 --dest /mnt/usb/backups

# Verify again, and restore
sudo target/release/partshield verify --report /mnt/usb/backups/home-XXXX.report.json
sudo target/release/partshield restore --report /mnt/usb/backups/home-XXXX.report.json \
    --to /mnt/new --as home
```

`partshield --help` lists the rest: `restore-layout` and `verify-report`.

## Development

```sh
cargo fmt --check && cargo clippy --workspace --all-targets && cargo test --workspace

# End-to-end tests: root and loop devices, never real disks
sudo PARTSHIELD_SANDBOX=1 PARTSHIELD_E2E=1 cargo test --test e2e --test raw_e2e --test multi_e2e
sudo PARTSHIELD_SANDBOX=1 PARTSHIELD_GUI_E2E=1 cargo test -p partshield-gui
```

With `PARTSHIELD_SANDBOX=1`, PartShield refuses to touch any `/dev/` that isn't
a loop device. Read [CONTRIBUTING.md](CONTRIBUTING.md) before contributing.

| Folder | What's inside |
| --- | --- |
| `crates/core` | The engine: detection, send, raw, verification and reports |
| `crates/cli` | The command line |
| `crates/gui` | The interface (GTK 4 + libadwaita) |
| `iso` | The live USB (live-build) and its QEMU boot tests |
| `web` | partshield.io |

## Roadmap

What's next (restoring from the GUI, real percentage progress, LUKS, GParted
on the ISO, English interface…) is in [ROADMAP.md](ROADMAP.md).

## License

[GPL-3.0 or later](LICENSE).
