//! Btrfs feature flags (values from the kernel's `uapi/linux/btrfs.h`).

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

macro_rules! flag_set {
    ($name:ident { $($flag:ident = $bit:expr),* $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(pub u64);

        impl $name {
            $(pub const $flag: u64 = 1 << $bit;)*
            const KNOWN: &'static [(&'static str, u64)] = &[$((stringify!($flag), 1 << $bit)),*];

            pub fn contains(self, flag: u64) -> bool {
                self.0 & flag == flag
            }

            pub fn names(self) -> Vec<&'static str> {
                Self::KNOWN.iter().filter(|(_, v)| self.0 & v != 0).map(|(n, _)| *n).collect()
            }

            /// Bits set that this build does not know about.
            pub fn unknown(self) -> u64 {
                let known = Self::KNOWN.iter().fold(0, |acc, (_, v)| acc | v);
                self.0 & !known
            }

            pub fn name_of(flag: u64) -> &'static str {
                Self::KNOWN.iter().find(|(_, v)| *v == flag).map(|(n, _)| *n).unwrap_or("UNKNOWN")
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let mut st = s.serialize_struct(stringify!($name), 3)?;
                st.serialize_field("raw", &format!("{:#x}", self.0))?;
                st.serialize_field("names", &self.names())?;
                st.serialize_field("unknown", &format!("{:#x}", self.unknown()))?;
                st.end()
            }
        }
    };
}

flag_set!(CompatRo {
    FREE_SPACE_TREE = 0,
    FREE_SPACE_TREE_VALID = 1,
    VERITY = 2,
    BLOCK_GROUP_TREE = 3,
});

flag_set!(Incompat {
    MIXED_BACKREF = 0,
    DEFAULT_SUBVOL = 1,
    MIXED_GROUPS = 2,
    COMPRESS_LZO = 3,
    COMPRESS_ZSTD = 4,
    BIG_METADATA = 5,
    EXTENDED_IREF = 6,
    RAID56 = 7,
    SKINNY_METADATA = 8,
    NO_HOLES = 9,
    METADATA_UUID = 10,
    RAID1C34 = 11,
    ZONED = 12,
    EXTENT_TREE_V2 = 13,
    RAID_STRIPE_TREE = 14,
    SIMPLE_QUOTA = 16,
});

#[derive(Debug, Clone, Serialize)]
pub struct Features {
    pub compat: u64,
    pub compat_ro: CompatRo,
    pub incompat: Incompat,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_btrfs_progs_dump() {
        // `dump-super` of a fresh `-O block-group-tree` filesystem.
        assert_eq!(
            CompatRo(0xb).names(),
            [
                "FREE_SPACE_TREE",
                "FREE_SPACE_TREE_VALID",
                "BLOCK_GROUP_TREE"
            ]
        );
        assert_eq!(
            Incompat(0x341).names(),
            [
                "MIXED_BACKREF",
                "EXTENDED_IREF",
                "SKINNY_METADATA",
                "NO_HOLES"
            ]
        );
    }

    #[test]
    fn reports_unknown_bits() {
        assert_eq!(CompatRo(0b1_0001).unknown(), 0b1_0000);
        assert_eq!(Incompat(1 << 15).unknown(), 1 << 15);
    }
}
