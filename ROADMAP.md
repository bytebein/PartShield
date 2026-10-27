# PartShield roadmap

The goal: a backup should take four clicks and one progress bar, with
everything else in an advanced mode.

## Before calling it 1.0

1. ~~Own repository with CI, README and license.~~ Done: `bytebein/PartShield`,
   GPL-3.0.
2. A real backup of an everyday disk (Btrfs, ~653 GiB), restored and verified
   end to end on real hardware.

## Done

- Home screen with "Back up" and "Restore" (Restore still pending), an
  "Advanced" switch and a "Tools" menu.
- Simple backup: whole disk or partitions with checkboxes, destination on
  another disk, one progress bar, and a green, amber or red result.
- Whole disk: partition table (`sfdisk --dump`) plus each partition; Btrfs
  via send, everything else sector by sector.
- "Structure" step for ext2/3/4, vfat, exFAT, XFS and NTFS using their
  read-only fsck, so backups of those partitions can come out valid.

## Simple mode

The default: the live USB always starts in simple mode.

**Home screen:** two buttons, "Back up" and "Restore".

**Back up**, Acronis style:

1. **Source:** disk tree. The whole disk is selected by default; single
   partitions can be picked too.
2. **Destination:** external disks only, with a fits / doesn't fit warning.
3. **Progress:** one bar covering copy and verification, with percentage
   and time left.
4. **Result:**
   - 🟢 Verified: safe to restore.
   - 🟡 Backed up, but not fully verified.
   - 🔴 This backup is not valid.

**Restore:** pick the backup (newest first), pick the disk, start.

Anything that erases a disk asks for confirmation by model and serial
number, in simple mode too.

What simple mode decides on its own:

- All subvolumes, no snapshots.
- Send or raw depending on what's on the disk.
- Full verification, always; it can't be skipped.
- Signed report saved next to the backup.

## Advanced mode

Turned on with a switch at the top. It includes:

- What exists today: subvolume selection, method, and the detail of the five
  verification steps.
- Extras:
  - include snapshots
  - exclusions
  - sample size
  - signing keys
  - live log
  - re-verify an old backup
  - unlock LUKS

## External drives

- All of them are mounted **read-only** at boot, and existing backups on
  them are offered under "Restore".
- Only the chosen destination becomes read-write, and only while copying.
- A mounted source is unmounted automatically before copying.

## Tools

A separate button for utilities:

- **GParted**, with Xwayland on the ISO. Root permissions inside cage still
  need solving: launch it as root, or add a polkit agent.
- Later: a terminal and disk SMART status.

PartShield doesn't format disks. If the destination isn't usable, prepare
it first with GParted.

## Interface language

- English interface (gettext), chosen from the system language or at boot,
  with Spanish kept as a translation.

## Technical work

- **Whole-disk backup:** partition table plus each partition.
  - Btrfs, as today.
  - NTFS, EFI and the rest as an image of used blocks only (today the whole
    partition is copied, free space included).
  - Each partition is verified by restoring it.
- **Dirty NTFS** (Windows hibernated or with Fast Startup): warn and don't
  copy.
- **Progress bar** with a real percentage. Today it advances per part (copy
  and verification); on a large sector-by-sector image it sits still until
  the copy finishes.
- **Restore from the GUI.**
- GParted and Xwayland on the ISO (the button already exists and turns on
  when GParted is installed).
