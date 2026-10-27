# Contributing to PartShield

PartShield writes to disks. That's why these rules aren't optional.

## Loop devices only

- **Never** test on `/dev/nvme*`, `/dev/sd*` or any real disk.
- Use loop devices backed by files inside a temporary directory.
- Always export `PARTSHIELD_SANDBOX=1`. With it, PartShield refuses any
  command naming a `/dev/` that isn't `/dev/loop*`, symlinks included. Code
  that opens a device directly goes through `cmd::guard_path`, which does the
  same check.
- Unmount a loop device before detaching it. Always release what you create,
  even when the test fails.

## "Done" means

1. `cargo fmt --check`, `cargo clippy --workspace --all-targets` with no
   warnings, and `cargo test --workspace` green.
2. The end-to-end tests, with root and loop devices:

   ```sh
   sudo PARTSHIELD_SANDBOX=1 PARTSHIELD_E2E=1 cargo test --test e2e --test raw_e2e --test multi_e2e
   sudo PARTSHIELD_SANDBOX=1 PARTSHIELD_GUI_E2E=1 cargo test -p partshield-gui
   ```

   The first one is the project's original gate: restore and mount a backup
   of a Btrfs with `BLOCK_GROUP_TREE`.
3. For the ISO: `iso/scripts/build-iso.sh` and its QEMU boot tests (BIOS,
   UEFI and Secure Boot).

Compiling isn't "done". Working in QEMU isn't "works on real hardware" either:
say which one it is in the PR.

## Layout

| Module | Contents |
| --- | --- |
| `crates/core/src/types.rs`, `cmd.rs`, `lib.rs` | Shared types, command execution and orchestration |
| `crates/core/src/detect/` | Superblock, features per mode, LUKS/LVM, disks |
| `crates/core/src/send/` | Snapshots, send/receive, zstd, incrementals, restore, partition table, ESP and UUID |
| `crates/core/src/raw/` | Sector-by-sector image and its verification |
| `crates/core/src/verify/` | Test restore and the five steps |
| `crates/core/src/report/` | JSON and HTML report, ed25519 signature |
| `crates/cli` | Command line |
| `crates/gui` | GTK 4 + libadwaita interface (simple mode in `basic.rs`) |
| `iso` | Live USB with live-build (Debian 13, Secure Boot) |

A change to the shared types (`types.rs`, `cmd.rs`) affects everything:
explain it in the PR.

## Style

- Existing code comments and interface text are in Spanish. New code and
  commit messages may be in English; the interface will move to gettext.
- Every external command goes through `Session`, which shows it and records it
  in the report: no bare `std::process::Command` in the engine.
- A backup is **valid** only if all five steps pass. Don't add shortcuts that
  mark a backup as good without restoring it.

## License

By contributing you agree that your code is published under the
[GPL-3.0 or later](LICENSE).
