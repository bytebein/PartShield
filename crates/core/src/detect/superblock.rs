//! Reads the Btrfs superblock (and its mirror copies) straight from a device
//! or image file.
//!
//! Parsing the raw bytes (instead of `btrfs inspect-internal dump-super` text)
//! keeps feature detection independent of btrfs-progs output formatting.
//!
//! Every copy is checked the way the kernel checks it: magic, `bytenr` equal
//! to the offset it was read from, and the checksum of bytes `0x20..4096`
//! with the filesystem's algorithm (crc32c, xxhash64, sha256 or blake2b).
//!
//! Not covered: zoned filesystems (`ZONED`), whose superblock lives in a
//! log-structured zone pair instead of these fixed offsets.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::csum;
use crate::types::{ChecksumStatus, CompatRo, FeatureSet, Incompat, Superblock};

pub const SUPER_OFFSET: u64 = 0x1_0000;
pub const SUPER_SIZE: usize = 4096;
/// Primary (64 KiB) and mirrors (64 MiB, 256 GiB): `btrfs_sb_offset()`.
pub const SUPER_MIRRORS: [u64; 3] = [SUPER_OFFSET, 0x400_0000, 0x40_0000_0000];
const MAGIC: &[u8; 8] = b"_BHRfS_M";
/// `dev_item` starts at 0xc9; `total_bytes` follows `devid`.
const DEV_ITEM_TOTAL_BYTES: u64 = 0xc9 + 8;

#[derive(Debug, thiserror::Error)]
pub enum SuperblockError {
    /// The cause is kept as `source` (not in the message) so an anyhow chain
    /// prints it once.
    #[error("no se pudo leer el superbloque de {}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Denied(String),
    #[error("superbloque truncado: {0} bytes de {SUPER_SIZE}")]
    TooShort(usize),
    #[error("no es un sistema de archivos Btrfs (magic incorrecto)")]
    BadMagic,
    #[error("superbloque en el offset {expected} dice estar en {found} (bytenr incorrecto)")]
    BadBytenr { expected: u64, found: u64 },
    #[error("checksum {algo} del superbloque incorrecto: guardado {stored}, calculado {computed}")]
    BadChecksum {
        algo: &'static str,
        stored: String,
        computed: String,
    },
}

/// Parsing lives here; the struct is shared (`types::Superblock`).
pub trait SuperblockExt: Sized {
    /// Reads and validates the primary superblock (64 KiB).
    fn read_from(path: &Path) -> Result<Self, SuperblockError>;
    /// Parses and validates a primary superblock.
    fn parse(buf: &[u8]) -> Result<Self, SuperblockError>;
}

impl SuperblockExt for Superblock {
    fn read_from(path: &Path) -> Result<Self, SuperblockError> {
        let mut f = open(path)?;
        read_at(&mut f, path, SUPER_OFFSET)
    }

    fn parse(buf: &[u8]) -> Result<Self, SuperblockError> {
        parse_at(buf, SUPER_OFFSET)
    }
}

fn open(path: &Path) -> Result<File, SuperblockError> {
    crate::cmd::guard_path(path).map_err(|e| SuperblockError::Denied(e.to_string()))?;
    File::open(path).map_err(|source| SuperblockError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn read_at(f: &mut File, path: &Path, offset: u64) -> Result<Superblock, SuperblockError> {
    let io = |source| SuperblockError::Io {
        path: path.to_path_buf(),
        source,
    };
    f.seek(SeekFrom::Start(offset)).map_err(io)?;
    let mut buf = vec![0u8; SUPER_SIZE];
    f.read_exact(&mut buf).map_err(io)?;
    parse_at(&buf, offset)
}

/// Parses a superblock read from `offset` and validates magic, `bytenr`
/// and checksum.
pub fn parse_at(buf: &[u8], offset: u64) -> Result<Superblock, SuperblockError> {
    if buf.len() < SUPER_SIZE {
        return Err(SuperblockError::TooShort(buf.len()));
    }
    if &buf[0x40..0x48] != MAGIC {
        return Err(SuperblockError::BadMagic);
    }
    let bytenr = u64_at(buf, 0x30);
    if bytenr != offset {
        return Err(SuperblockError::BadBytenr {
            expected: offset,
            found: bytenr,
        });
    }

    let csum_type = u16_at(buf, 0xc4);
    let checksum = match csum::compute(csum_type, &buf[0x20..SUPER_SIZE]) {
        Some(computed) => {
            let stored = &buf[..computed.len()];
            if stored != computed.as_slice() {
                return Err(SuperblockError::BadChecksum {
                    algo: csum::name(csum_type),
                    stored: hex(stored),
                    computed: hex(&computed),
                });
            }
            ChecksumStatus::Valid
        }
        // An algorithm newer than this build: the kernel would refuse it too,
        // but the features are still worth reporting.
        None => ChecksumStatus::NotVerified { csum_type },
    };

    let label_raw = &buf[0x12b..0x12b + 256];
    let label_len = label_raw.iter().position(|&b| b == 0).unwrap_or(256);

    Ok(Superblock {
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
        features: FeatureSet {
            compat: u64_at(buf, 0xac),
            compat_ro: CompatRo(u64_at(buf, 0xb4)),
            incompat: Incompat(u64_at(buf, 0xbc)),
        },
    })
}

// ------------------------------------------------------- todas las copias

/// What was found at one superblock offset.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CopyStatus {
    Valid {
        superblock: Box<Superblock>,
    },
    /// Device too small for this mirror; Btrfs does not write it.
    Absent,
    Invalid {
        error: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct SuperblockCopy {
    pub index: usize,
    pub offset: u64,
    #[serde(flatten)]
    pub status: CopyStatus,
}

impl SuperblockCopy {
    pub fn superblock(&self) -> Option<&Superblock> {
        match &self.status {
            CopyStatus::Valid { superblock } => Some(superblock),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SuperblockCopies {
    pub device_size: u64,
    pub copies: Vec<SuperblockCopy>,
}

impl SuperblockCopies {
    pub fn primary(&self) -> Option<&Superblock> {
        self.copies.first().and_then(SuperblockCopy::superblock)
    }

    /// Problems worth showing: a mirror that should exist but is invalid,
    /// or copies that disagree on generation or fsid. Empty means every copy
    /// the device can hold is valid and identical in those fields.
    pub fn discrepancies(&self) -> Vec<String> {
        let mut out = Vec::new();
        let valid: Vec<(usize, &Superblock)> = self
            .copies
            .iter()
            .filter_map(|c| c.superblock().map(|s| (c.index, s)))
            .collect();
        for c in &self.copies {
            if let CopyStatus::Invalid { error } = &c.status {
                out.push(format!(
                    "copia {} del superbloque (offset {}): {error}",
                    c.index, c.offset
                ));
            }
        }
        if let Some((i0, first)) = valid.first() {
            for (i, sb) in &valid[1..] {
                if sb.generation != first.generation {
                    out.push(format!(
                        "la copia {i} del superbloque tiene generation {} y la copia {i0} {}",
                        sb.generation, first.generation
                    ));
                }
                if sb.fsid != first.fsid {
                    out.push(format!(
                        "la copia {i} del superbloque es de otro sistema de archivos ({} frente a {})",
                        sb.fsid, first.fsid
                    ));
                }
            }
        }
        out
    }
}

/// Reads every superblock copy the device is large enough to hold
/// (64 KiB, 64 MiB, 256 GiB). Fails only if the device cannot be opened or
/// sized; a bad copy is reported in its entry.
pub fn read_all_copies(path: &Path) -> Result<SuperblockCopies, SuperblockError> {
    let mut f = open(path)?;
    // Works for regular files and block devices alike.
    let device_size = f
        .seek(SeekFrom::End(0))
        .map_err(|source| SuperblockError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    // The kernel writes a mirror only if it ends before the Btrfs device
    // size (`dev_item.total_bytes`), which can be smaller than the block
    // device after a shrink; take the smaller of the two.
    let mut limit = device_size;
    let mut copies = Vec::new();
    for (index, &offset) in SUPER_MIRRORS.iter().enumerate() {
        let status = if offset + SUPER_SIZE as u64 >= limit {
            CopyStatus::Absent
        } else {
            match read_at(&mut f, path, offset) {
                Ok(sb) => {
                    if index == 0 {
                        limit = limit.min(dev_total_bytes(&mut f).unwrap_or(limit));
                    }
                    CopyStatus::Valid {
                        superblock: Box::new(sb),
                    }
                }
                Err(e) => CopyStatus::Invalid {
                    error: error_chain(&e),
                },
            }
        };
        copies.push(SuperblockCopy {
            index,
            offset,
            status,
        });
    }
    Ok(SuperblockCopies {
        device_size,
        copies,
    })
}

/// `dev_item.total_bytes` of the primary superblock (already validated).
fn dev_total_bytes(f: &mut File) -> Option<u64> {
    let mut b = [0u8; 8];
    f.seek(SeekFrom::Start(SUPER_OFFSET + DEV_ITEM_TOTAL_BYTES))
        .ok()?;
    f.read_exact(&mut b).ok()?;
    Some(u64::from_le_bytes(b)).filter(|&n| n > 0)
}

fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn uuid(b: &[u8]) -> String {
    let h = hex(b);
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
    use std::io::Write;

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

    /// Recomputes the checksum with the buffer's own `csum_type`.
    pub(crate) fn reseal(b: &mut [u8]) {
        let c = csum::compute(u16_at(b, 0xc4), &b[0x20..SUPER_SIZE]).unwrap();
        b[..32].fill(0);
        b[..c.len()].copy_from_slice(&c);
    }

    fn with_csum(csum_type: u16) -> Vec<u8> {
        let mut b = sample();
        b[0xc4..0xc6].copy_from_slice(&csum_type.to_le_bytes());
        reseal(&mut b);
        b
    }

    fn mirror(mut b: Vec<u8>, offset: u64, generation: u64) -> Vec<u8> {
        b[0x30..0x38].copy_from_slice(&offset.to_le_bytes());
        b[0x48..0x50].copy_from_slice(&generation.to_le_bytes());
        reseal(&mut b);
        b
    }

    fn image(size: u64, blocks: &[(u64, Vec<u8>)]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.as_file().set_len(size).unwrap();
        for (off, b) in blocks {
            f.seek(SeekFrom::Start(*off)).unwrap();
            f.write_all(b).unwrap();
        }
        f
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
            Err(SuperblockError::BadChecksum { algo: "crc32c", .. })
        ));
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(matches!(
            Superblock::parse(&[0u8; 100]),
            Err(SuperblockError::TooShort(100))
        ));
    }

    #[test]
    fn rejects_wrong_bytenr() {
        // A mirror copy (bytenr 64 MiB) is not a valid primary.
        let b = mirror(sample(), SUPER_MIRRORS[1], 6);
        match Superblock::parse(&b) {
            Err(SuperblockError::BadBytenr { expected, found }) => {
                assert_eq!((expected, found), (SUPER_OFFSET, SUPER_MIRRORS[1]));
            }
            other => panic!("{other:?}"),
        }
        assert!(parse_at(&b, SUPER_MIRRORS[1]).is_ok());
    }

    #[test]
    fn verifies_every_known_checksum() {
        for t in [csum::CRC32C, csum::XXHASH64, csum::SHA256, csum::BLAKE2B] {
            let b = with_csum(t);
            assert_eq!(
                Superblock::parse(&b).unwrap().checksum,
                ChecksumStatus::Valid,
                "{}",
                csum::name(t)
            );
            let mut bad = b.clone();
            bad[0x200] ^= 1;
            assert!(
                matches!(
                    Superblock::parse(&bad),
                    Err(SuperblockError::BadChecksum { .. })
                ),
                "{}",
                csum::name(t)
            );
        }
    }

    #[test]
    fn unknown_checksum_type_is_not_verified() {
        let mut b = sample();
        b[0xc4..0xc6].copy_from_slice(&7u16.to_le_bytes());
        assert_eq!(
            Superblock::parse(&b).unwrap().checksum,
            ChecksumStatus::NotVerified { csum_type: 7 }
        );
    }

    #[test]
    fn io_error_names_the_cause_once() {
        let e = Superblock::read_from(Path::new("/nonexistent/partshield.img")).unwrap_err();
        let msg = format!("{:#}", anyhow::Error::from(e));
        assert_eq!(msg.matches("No such file or directory").count(), 1, "{msg}");
        assert!(msg.contains("/nonexistent/partshield.img"), "{msg}");
    }

    #[test]
    fn small_device_has_only_the_primary() {
        let img = image(1 << 20, &[(SUPER_OFFSET, sample())]);
        let all = read_all_copies(img.path()).unwrap();
        assert_eq!(all.device_size, 1 << 20);
        assert!(all.primary().is_some());
        assert!(matches!(all.copies[1].status, CopyStatus::Absent));
        assert!(matches!(all.copies[2].status, CopyStatus::Absent));
        assert!(all.discrepancies().is_empty());
    }

    #[test]
    fn mirror_with_other_generation_is_reported() {
        let size = SUPER_MIRRORS[1] + (1 << 20);
        let img = image(
            size,
            &[
                (SUPER_OFFSET, sample()),
                (SUPER_MIRRORS[1], mirror(sample(), SUPER_MIRRORS[1], 5)),
            ],
        );
        let all = read_all_copies(img.path()).unwrap();
        assert_eq!(all.copies[1].superblock().unwrap().generation, 5);
        let d = all.discrepancies();
        assert_eq!(d.len(), 1, "{d:?}");
        assert!(d[0].contains("generation 5"), "{d:?}");

        let same = image(
            size,
            &[
                (SUPER_OFFSET, sample()),
                (SUPER_MIRRORS[1], mirror(sample(), SUPER_MIRRORS[1], 6)),
            ],
        );
        assert!(read_all_copies(same.path())
            .unwrap()
            .discrepancies()
            .is_empty());
    }

    #[test]
    fn missing_mirror_is_reported() {
        // Device big enough for the 64 MiB mirror, but nothing there.
        let img = image(SUPER_MIRRORS[1] + 8192, &[(SUPER_OFFSET, sample())]);
        let all = read_all_copies(img.path()).unwrap();
        assert!(matches!(all.copies[1].status, CopyStatus::Invalid { .. }));
        assert!(all.discrepancies()[0].contains("magic"));
    }

    #[test]
    fn real_mkfs_images_for_every_checksum() {
        // Cross-checks the hand-written xxhash64/blake2b against btrfs-progs.
        use crate::cmd::{Cmd, Session};
        let mut s = Session::new(false);
        if s.run(Cmd::new("mkfs.btrfs").arg("--version")).is_err() {
            eprintln!("mkfs.btrfs no está instalado; se omite");
            return;
        }
        for (name, t) in [
            ("crc32c", csum::CRC32C),
            ("xxhash", csum::XXHASH64),
            ("sha256", csum::SHA256),
            ("blake2", csum::BLAKE2B),
        ] {
            let img = image(SUPER_MIRRORS[1] + (64 << 20), &[]);
            s.run(
                Cmd::new("mkfs.btrfs")
                    .arg("-q")
                    .arg("-f")
                    .arg("--csum")
                    .arg(name)
                    .arg("-O")
                    .arg("block-group-tree")
                    .arg(img.path()),
            )
            .unwrap();
            let all = read_all_copies(img.path()).unwrap();
            let sb = all.primary().unwrap_or_else(|| panic!("{name}: {all:?}"));
            assert_eq!(sb.csum_type, t);
            assert_eq!(sb.checksum, ChecksumStatus::Valid);
            assert!(all.copies[1].superblock().is_some(), "{name}: {all:?}");
            assert!(all.discrepancies().is_empty(), "{name}");
        }
    }
}
