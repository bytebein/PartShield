//! Decides which copy modes are safe for a given filesystem.
//!
//! - `send` works at file level (`btrfs send`/`receive`), so on-disk features
//!   do not matter as long as the running kernel can mount the filesystem.
//!   With the kernel's feature list (`/sys/fs/btrfs/features`) a feature it
//!   does not list blocks the mode; without it, send is allowed (the source
//!   is mounted, so the kernel already understands it).
//! - `partclone` copies blocks, so the copier must understand every on-disk
//!   feature: only partclone ≥ `PARTCLONE_MIN` and only the tested list.
//!   Anything else, including bits this build cannot name, disables the mode
//!   instead of producing a backup that may silently miss metadata
//!   (partclone #303).
//! - `raw` copies every sector and is always allowed.

use std::collections::BTreeSet;
use std::path::Path;

use crate::types::{Assessment, CompatRo, FeatureSet, Incompat, Mode, Version};

/// partclone version with the BLOCK_GROUP_TREE fix (0.3.49) plus the
/// multi-level tree fix (0.3.50).
pub const PARTCLONE_MIN: Version = Version(0, 3, 50);

/// FeatureSet partclone handles from `PARTCLONE_MIN` on, as covered by its
/// regression tests and ours.
pub const PARTCLONE_COMPAT_RO: u64 =
    CompatRo::FREE_SPACE_TREE | CompatRo::FREE_SPACE_TREE_VALID | CompatRo::BLOCK_GROUP_TREE;
pub const PARTCLONE_INCOMPAT: u64 = Incompat::MIXED_BACKREF
    | Incompat::DEFAULT_SUBVOL
    | Incompat::COMPRESS_LZO
    | Incompat::COMPRESS_ZSTD
    | Incompat::BIG_METADATA
    | Incompat::EXTENDED_IREF
    | Incompat::SKINNY_METADATA
    | Incompat::NO_HOLES;

/// Features the kernel supports without listing them in sysfs.
const KERNEL_IMPLICIT_COMPAT_RO: u64 = CompatRo::FREE_SPACE_TREE_VALID;
const KERNEL_IMPLICIT_INCOMPAT: u64 = Incompat::MIXED_BACKREF | Incompat::BIG_METADATA;

type FlagName = fn(u64) -> &'static str;

/// Feature names the running kernel lists in `/sys/fs/btrfs/features`
/// (lowercase, e.g. `block_group_tree`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelFeatures(pub BTreeSet<String>);

impl KernelFeatures {
    pub const SYSFS: &'static str = "/sys/fs/btrfs/features";

    /// `None` if the directory does not exist (btrfs not loaded, or not Linux).
    pub fn from_sysfs() -> Option<Self> {
        Self::from_dir(Path::new(Self::SYSFS))
    }

    pub fn from_dir(dir: &Path) -> Option<Self> {
        let names = std::fs::read_dir(dir)
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        Some(Self(names))
    }

    fn supports(&self, name: &str) -> bool {
        self.0.contains(&name.to_ascii_lowercase())
    }
}

/// Assessment without knowing the kernel (send allowed).
pub fn assess(features: &FeatureSet, partclone: Option<Version>) -> Vec<Assessment> {
    assess_with_kernel(features, partclone, None)
}

pub fn assess_with_kernel(
    features: &FeatureSet,
    partclone: Option<Version>,
    kernel: Option<&KernelFeatures>,
) -> Vec<Assessment> {
    vec![
        assess_send(features, kernel),
        assess_partclone(features, partclone),
        Assessment {
            mode: Mode::Raw,
            allowed: true,
            reasons: vec![],
        },
    ]
}

fn set_bits(bits: u64) -> impl Iterator<Item = u64> {
    (0..64).map(|i| 1u64 << i).filter(move |b| bits & b != 0)
}

fn describe(bit: u64, name_of: FlagName) -> String {
    match name_of(bit) {
        "UNKNOWN" => format!("bit {} desconocido ({bit:#x})", bit.trailing_zeros()),
        name => name.to_string(),
    }
}

fn assess_send(features: &FeatureSet, kernel: Option<&KernelFeatures>) -> Assessment {
    let mut reasons = Vec::new();
    if let Some(k) = kernel {
        let named: [(u64, FlagName); 2] = [
            (
                features.compat_ro.0 & !KERNEL_IMPLICIT_COMPAT_RO,
                CompatRo::name_of,
            ),
            (
                features.incompat.0 & !KERNEL_IMPLICIT_INCOMPAT,
                Incompat::name_of,
            ),
        ];
        for (bits, name_of) in named {
            for bit in set_bits(bits) {
                let name = name_of(bit);
                // Unnamed bits cannot be looked up; if the source is
                // mounted, the kernel understands them.
                if name != "UNKNOWN" && !k.supports(name) {
                    reasons.push(format!(
                        "el kernel en ejecución no soporta {name}; no podría montar ni restaurar este sistema de archivos"
                    ));
                }
            }
        }
    }
    Assessment {
        mode: Mode::Send,
        allowed: reasons.is_empty(),
        reasons,
    }
}

fn assess_partclone(features: &FeatureSet, version: Option<Version>) -> Assessment {
    let mut reasons = Vec::new();
    match version {
        None => reasons.push("partclone.btrfs no está instalado".to_string()),
        Some(v) if v < PARTCLONE_MIN => reasons.push(format!(
            "partclone {v} es anterior a {PARTCLONE_MIN}, que corrige la copia de BLOCK_GROUP_TREE"
        )),
        Some(_) => {}
    }
    if features.compat != 0 {
        reasons.push(format!("compat_flags desconocidas: {:#x}", features.compat));
    }
    let untested: [(u64, FlagName); 2] = [
        (
            features.compat_ro.0 & !PARTCLONE_COMPAT_RO,
            CompatRo::name_of,
        ),
        (features.incompat.0 & !PARTCLONE_INCOMPAT, Incompat::name_of),
    ];
    for (bits, name_of) in untested {
        for bit in set_bits(bits) {
            reasons.push(format!(
                "feature no probada con partclone: {}",
                describe(bit, name_of)
            ));
        }
    }
    Assessment {
        mode: Mode::Partclone,
        allowed: reasons.is_empty(),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: Option<Version> = Some(PARTCLONE_MIN);

    fn feats(compat_ro: u64, incompat: u64) -> FeatureSet {
        FeatureSet {
            compat: 0,
            compat_ro: CompatRo(compat_ro),
            incompat: Incompat(incompat),
        }
    }

    fn find(a: &[Assessment], mode: Mode) -> &Assessment {
        a.iter().find(|x| x.mode == mode).unwrap()
    }

    fn partclone(a: &[Assessment]) -> &Assessment {
        find(a, Mode::Partclone)
    }

    /// Every named flag in a set, with its name.
    fn all_named<F: Fn(u64) -> &'static str>(name_of: F) -> Vec<(u64, &'static str)> {
        set_bits(u64::MAX)
            .map(|b| (b, name_of(b)))
            .filter(|(_, n)| *n != "UNKNOWN")
            .collect()
    }

    fn kernel(names: &[&str]) -> KernelFeatures {
        KernelFeatures(names.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn rescuezilla_partclone_is_blocked_on_bgt() {
        // The setup from partclone #303: BGT + zstd, partclone 0.3.47.
        let f = feats(0xb, 0x341 | Incompat::COMPRESS_ZSTD);
        let a = assess(&f, Some(Version(0, 3, 47)));
        assert!(!partclone(&a).allowed);
        assert!(partclone(&a).reasons[0].contains("0.3.47"));
        assert!(find(&a, Mode::Send).allowed);
    }

    #[test]
    fn partclone_0_3_49_is_still_blocked() {
        // 0.3.49 fixed BGT but not multi-level trees.
        let a = assess(&feats(0xb, 0x341), Some(Version(0, 3, 49)));
        assert!(!partclone(&a).allowed);
    }

    #[test]
    fn missing_partclone_is_blocked() {
        let a = assess(&feats(0, 0), None);
        assert!(!partclone(&a).allowed);
        assert!(partclone(&a).reasons[0].contains("no está instalado"));
    }

    #[test]
    fn current_partclone_is_allowed_on_bgt() {
        let a = assess(&feats(0xb, 0x341), OK);
        assert!(partclone(&a).allowed, "{:?}", partclone(&a).reasons);
        let newer = assess(&feats(0xb, 0x341), Some(Version(0, 4, 0)));
        assert!(partclone(&newer).allowed);
    }

    #[test]
    fn every_tested_feature_alone_is_allowed() {
        for (bit, name) in all_named(CompatRo::name_of) {
            let a = assess(&feats(bit, 0), OK);
            assert_eq!(
                partclone(&a).allowed,
                PARTCLONE_COMPAT_RO & bit != 0,
                "{name}: {:?}",
                partclone(&a).reasons
            );
        }
        for (bit, name) in all_named(Incompat::name_of) {
            let a = assess(&feats(0, bit), OK);
            assert_eq!(
                partclone(&a).allowed,
                PARTCLONE_INCOMPAT & bit != 0,
                "{name}: {:?}",
                partclone(&a).reasons
            );
        }
    }

    #[test]
    fn untested_features_block_partclone_by_name() {
        for (ro, inc, name) in [
            (CompatRo::VERITY, 0, "VERITY"),
            (0, Incompat::MIXED_GROUPS, "MIXED_GROUPS"),
            (0, Incompat::RAID56, "RAID56"),
            (0, Incompat::METADATA_UUID, "METADATA_UUID"),
            (0, Incompat::RAID1C34, "RAID1C34"),
            (0, Incompat::ZONED, "ZONED"),
            (0, Incompat::EXTENT_TREE_V2, "EXTENT_TREE_V2"),
            (0, Incompat::RAID_STRIPE_TREE, "RAID_STRIPE_TREE"),
            (0, Incompat::SIMPLE_QUOTA, "SIMPLE_QUOTA"),
        ] {
            let a = assess(&feats(0x3 | ro, inc), OK);
            let p = partclone(&a);
            assert!(!p.allowed, "{name}");
            assert_eq!(p.reasons.len(), 1, "{name}: {:?}", p.reasons);
            assert!(p.reasons[0].contains(name), "{:?}", p.reasons);
        }
    }

    #[test]
    fn unknown_bits_block_partclone() {
        let a = assess(&feats(1 << 20, 0), OK);
        assert!(partclone(&a).reasons[0].contains("bit 20 desconocido"));
        // Bit 15 of incompat is unassigned in the kernel.
        let a = assess(&feats(0, 1 << 15), OK);
        assert!(!partclone(&a).allowed);
        assert!(partclone(&a).reasons[0].contains("bit 15"));
        let a = assess(&feats(0, 1 << 63), OK);
        assert!(partclone(&a).reasons[0].contains("bit 63"));
    }

    #[test]
    fn compat_flags_block_partclone() {
        let mut f = feats(0, 0);
        f.compat = 1;
        let a = assess(&f, OK);
        assert!(!partclone(&a).allowed);
        assert!(partclone(&a).reasons[0].contains("compat_flags"));
    }

    #[test]
    fn every_reason_is_listed() {
        let a = assess(
            &feats(CompatRo::VERITY | 1 << 9, Incompat::RAID56),
            Some(Version(0, 3, 47)),
        );
        // version + VERITY + bit 9 + RAID56
        assert_eq!(
            partclone(&a).reasons.len(),
            4,
            "{:?}",
            partclone(&a).reasons
        );
    }

    #[test]
    fn send_and_raw_are_always_allowed_without_kernel_info() {
        let mut f = feats(u64::MAX, u64::MAX);
        f.compat = u64::MAX;
        let a = assess(&f, None);
        assert!(find(&a, Mode::Send).allowed);
        assert!(find(&a, Mode::Raw).allowed);
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn send_needs_kernel_support() {
        // What this machine's kernel (6.18, no verity/zoned) lists.
        let k = kernel(&[
            "block_group_tree",
            "compress_lzo",
            "compress_zstd",
            "default_subvol",
            "extended_iref",
            "free_space_tree",
            "metadata_uuid",
            "mixed_groups",
            "no_holes",
            "raid1c34",
            "raid56",
            "simple_quota",
            "skinny_metadata",
        ]);
        let ok = assess_with_kernel(&feats(0xb, 0x341 | Incompat::BIG_METADATA), OK, Some(&k));
        assert!(find(&ok, Mode::Send).allowed, "{:?}", find(&ok, Mode::Send));

        let a = assess_with_kernel(
            &feats(0xb | CompatRo::VERITY, Incompat::EXTENT_TREE_V2),
            OK,
            Some(&k),
        );
        let send = find(&a, Mode::Send);
        assert!(!send.allowed);
        assert_eq!(send.reasons.len(), 2, "{:?}", send.reasons);
        assert!(send.reasons[0].contains("VERITY"));
        assert!(send.reasons[1].contains("EXTENT_TREE_V2"));
        assert!(find(&a, Mode::Raw).allowed);

        // Unnamed bits do not block send.
        let a = assess_with_kernel(&feats(1 << 30, 0), OK, Some(&k));
        assert!(find(&a, Mode::Send).allowed);
    }

    #[test]
    fn kernel_features_from_dir() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("block_group_tree"), "0\n").unwrap();
        let k = KernelFeatures::from_dir(d.path()).unwrap();
        assert!(k.supports("BLOCK_GROUP_TREE"));
        assert!(!k.supports("ZONED"));
        assert!(KernelFeatures::from_dir(&d.path().join("no")).is_none());
    }

    #[test]
    fn version_parsing() {
        assert_eq!(
            Version::find_in("Partclone v0.3.50 http://partclone.org"),
            Some(Version(0, 3, 50))
        );
        assert_eq!(Version::find_in("no version"), None);
        assert!(Version(0, 3, 47) < PARTCLONE_MIN);
    }
}
