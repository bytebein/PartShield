//! Decides which copy modes are safe for a given filesystem.
//!
//! Image modes copy blocks, so the copier must understand every on-disk
//! feature. Anything not on the tested list disables that mode instead of
//! producing a backup that may silently miss metadata (partclone #303).

use crate::types::{Assessment, CompatRo, FeatureSet, Incompat, Mode, Version};

/// partclone version with the BLOCK_GROUP_TREE fix (0.3.49) plus the
/// multi-level tree fix (0.3.50).
pub const PARTCLONE_MIN: Version = Version(0, 3, 50);

/// FeatureSet partclone handles from `PARTCLONE_MIN` on, as covered by its
/// regression tests and ours.
const PARTCLONE_COMPAT_RO: u64 =
    CompatRo::FREE_SPACE_TREE | CompatRo::FREE_SPACE_TREE_VALID | CompatRo::BLOCK_GROUP_TREE;
const PARTCLONE_INCOMPAT: u64 = Incompat::MIXED_BACKREF
    | Incompat::DEFAULT_SUBVOL
    | Incompat::COMPRESS_LZO
    | Incompat::COMPRESS_ZSTD
    | Incompat::BIG_METADATA
    | Incompat::EXTENDED_IREF
    | Incompat::SKINNY_METADATA
    | Incompat::NO_HOLES;

type FlagName = fn(u64) -> &'static str;

pub fn assess(features: &FeatureSet, partclone: Option<Version>) -> Vec<Assessment> {
    vec![
        Assessment {
            mode: Mode::Send,
            allowed: true,
            reasons: vec![],
        },
        assess_partclone(features, partclone),
        Assessment {
            mode: Mode::Raw,
            allowed: true,
            reasons: vec![],
        },
    ]
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
        for bit in (0..64).map(|i| 1u64 << i).filter(|b| bits & b != 0) {
            reasons.push(format!(
                "feature no probada con partclone: {}",
                name_of(bit)
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

    fn feats(compat_ro: u64, incompat: u64) -> FeatureSet {
        FeatureSet {
            compat: 0,
            compat_ro: CompatRo(compat_ro),
            incompat: Incompat(incompat),
        }
    }

    fn partclone(a: &[Assessment]) -> &Assessment {
        a.iter().find(|x| x.mode == Mode::Partclone).unwrap()
    }

    #[test]
    fn rescuezilla_partclone_is_blocked_on_bgt() {
        // The setup from partclone #303: BGT + zstd, partclone 0.3.47.
        let f = feats(0xb, 0x341 | Incompat::COMPRESS_ZSTD);
        let a = assess(&f, Some(Version(0, 3, 47)));
        assert!(!partclone(&a).allowed);
        assert!(a.iter().find(|x| x.mode == Mode::Send).unwrap().allowed);
    }

    #[test]
    fn current_partclone_is_allowed_on_bgt() {
        let a = assess(&feats(0xb, 0x341), Some(Version(0, 3, 50)));
        assert!(partclone(&a).allowed, "{:?}", partclone(&a).reasons);
    }

    #[test]
    fn untested_feature_blocks_partclone() {
        let a = assess(
            &feats(0x3, Incompat::RAID_STRIPE_TREE),
            Some(Version(0, 3, 50)),
        );
        let p = partclone(&a);
        assert!(!p.allowed);
        assert!(p.reasons.iter().any(|r| r.contains("RAID_STRIPE_TREE")));
    }

    #[test]
    fn unknown_bit_blocks_partclone() {
        let a = assess(&feats(1 << 20, 0), Some(Version(0, 3, 50)));
        assert!(partclone(&a).reasons.iter().any(|r| r.contains("UNKNOWN")));
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
