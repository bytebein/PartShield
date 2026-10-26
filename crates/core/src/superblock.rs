//! Reads the primary Btrfs superblock straight from a device or image file.
//!
//! Parsing the raw bytes (instead of `btrfs inspect-internal dump-super` text)
//! keeps feature detection independent of btrfs-progs output formatting.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde::Serialize;

use crate::features::{CompatRo, Features, Incompat};

pub const SUPER_OFFSET: u64 = 0x1_0000;
pub const SUPER_SIZE: usize = 4096;
const MAGIC: &[u8; 8] = b"_BHRfS_M";
const CSUM_TYPE_CRC32C: u16 = 0;

#[derive(Debug, thiserror::Error)]
pub enum SuperblockError {
    #[error("no se pudo leer el superbloque: {0}")]
    Io(#[from] std::io::Error),
    #[error("no es un sistema de archivos Btrfs (magic incorrecto)")]
    BadMagic,
    #[error(
        "checksum del superbloque incorrecto: guardado {stored:#010x}, calculado {computed:#010x}"
    )]
    BadChecksum { stored: u32, computed: u32 },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum ChecksumStatus {
    /// crc32c verified.
    Valid,
    /// The filesystem uses xxhash/sha256/blake2; not verified here.
    NotVerified { csum_type: u16 },
}

#[derive(Debug, Clone, Serialize)]
pub struct Superblock {
    pub fsid: String,
    pub label: String,
    pub generation: u64,
    pub root: u64,
    pub chunk_root: u64,
    pub chunk_root_level: u8,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub num_devices: u64,
    pub sectorsize: u32,
    pub nodesize: u32,
    pub csum_type: u16,
    pub checksum: ChecksumStatus,
    pub features: Features,
}

impl Superblock {
    pub fn read_from(path: &Path) -> Result<Self, SuperblockError> {
        let mut f = File::open(path)?;
        f.seek(SeekFrom::Start(SUPER_OFFSET))?;
        let mut buf = vec![0u8; SUPER_SIZE];
        f.read_exact(&mut buf)?;
        Self::parse(&buf)
    }

    pub fn parse(buf: &[u8]) -> Result<Self, SuperblockError> {
        assert!(buf.len() >= SUPER_SIZE, "superblock buffer too short");
        if &buf[0x40..0x48] != MAGIC {
            return Err(SuperblockError::BadMagic);
        }

        let csum_type = u16_at(buf, 0xc4);
        let checksum = if csum_type == CSUM_TYPE_CRC32C {
            let stored = u32_at(buf, 0x00);
            let computed = crc32c::crc32c(&buf[0x20..SUPER_SIZE]);
            if stored != computed {
                return Err(SuperblockError::BadChecksum { stored, computed });
            }
            ChecksumStatus::Valid
        } else {
            ChecksumStatus::NotVerified { csum_type }
        };

        let label_raw = &buf[0x12b..0x12b + 256];
        let label_len = label_raw.iter().position(|&b| b == 0).unwrap_or(256);

        Ok(Self {
            fsid: uuid(&buf[0x20..0x30]),
            label: String::from_utf8_lossy(&label_raw[..label_len]).into_owned(),
            generation: u64_at(buf, 0x48),
            root: u64_at(buf, 0x50),
            chunk_root: u64_at(buf, 0x58),
            chunk_root_level: buf[0xc7],
            total_bytes: u64_at(buf, 0x70),
            bytes_used: u64_at(buf, 0x78),
            num_devices: u64_at(buf, 0x88),
            sectorsize: u32_at(buf, 0x90),
            nodesize: u32_at(buf, 0x94),
            csum_type,
            checksum,
            features: Features {
                compat: u64_at(buf, 0xac),
                compat_ro: CompatRo(u64_at(buf, 0xb4)),
                incompat: Incompat(u64_at(buf, 0xbc)),
            },
        })
    }
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

fn uuid(b: &[u8]) -> String {
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds a minimal valid superblock with the values of a real
    /// `mkfs.btrfs -O block-group-tree` image (btrfs-progs 6.6.3).
    pub(crate) fn sample() -> Vec<u8> {
        let mut b = vec![0u8; SUPER_SIZE];
        let fsid = [
            0x85, 0x65, 0x46, 0xef, 0x38, 0xb5, 0x40, 0x81, 0x8d, 0xbd, 0x85, 0xec, 0x99, 0xb7,
            0x26, 0x76,
        ];
        b[0x20..0x30].copy_from_slice(&fsid);
        b[0x30..0x38].copy_from_slice(&SUPER_OFFSET.to_le_bytes());
        b[0x40..0x48].copy_from_slice(MAGIC);
        b[0x48..0x50].copy_from_slice(&6u64.to_le_bytes());
        b[0x50..0x58].copy_from_slice(&30_621_696u64.to_le_bytes());
        b[0x58..0x60].copy_from_slice(&22_036_480u64.to_le_bytes());
        b[0x70..0x78].copy_from_slice(&314_572_800u64.to_le_bytes());
        b[0x78..0x80].copy_from_slice(&163_840u64.to_le_bytes());
        b[0x88..0x90].copy_from_slice(&1u64.to_le_bytes());
        b[0x90..0x94].copy_from_slice(&4096u32.to_le_bytes());
        b[0x94..0x98].copy_from_slice(&16384u32.to_le_bytes());
        b[0xb4..0xbc].copy_from_slice(&0xbu64.to_le_bytes());
        b[0xbc..0xc4].copy_from_slice(&0x341u64.to_le_bytes());
        b[0x12b..0x12b + 4].copy_from_slice(b"casa");
        reseal(&mut b);
        b
    }

    pub(crate) fn reseal(b: &mut [u8]) {
        let c = crc32c::crc32c(&b[0x20..SUPER_SIZE]);
        b[0..4].copy_from_slice(&c.to_le_bytes());
    }

    #[test]
    fn parses_real_values() {
        let sb = Superblock::parse(&sample()).unwrap();
        assert_eq!(sb.fsid, "856546ef-38b5-4081-8dbd-85ec99b72676");
        assert_eq!(sb.label, "casa");
        assert_eq!(sb.chunk_root, 22_036_480);
        assert_eq!(sb.total_bytes, 314_572_800);
        assert_eq!(sb.nodesize, 16384);
        assert_eq!(sb.checksum, ChecksumStatus::Valid);
        assert!(sb.features.compat_ro.contains(CompatRo::BLOCK_GROUP_TREE));
        assert!(sb.features.incompat.contains(Incompat::NO_HOLES));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = sample();
        b[0x40] = b'X';
        assert!(matches!(
            Superblock::parse(&b),
            Err(SuperblockError::BadMagic)
        ));
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut b = sample();
        b[0x58] ^= 0xff;
        assert!(matches!(
            Superblock::parse(&b),
            Err(SuperblockError::BadChecksum { .. })
        ));
    }
}
