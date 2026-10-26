//! Tipos compartidos del motor. Los cambios aquí pasan por el lead: cada
//! módulo (detect, send, verify, report) los usa pero no los redefine.
//!
//! Feature flags: valores de `uapi/linux/btrfs.h` del kernel.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::{DateTime, Local};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};

use crate::cmd::{CommandRecord, Session};

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
pub struct FeatureSet {
    pub compat: u64,
    pub compat_ro: CompatRo,
    pub incompat: Incompat,
}

// ---------------------------------------------------------------- modos

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// `btrfs send` per subvolume. Works at file level, so it is valid for
    /// any feature the running kernel can mount.
    Send,
    /// Used-blocks image with partclone.btrfs.
    Partclone,
    /// Every sector, compressed.
    Raw,
}

#[derive(Debug, Clone, Serialize)]
pub struct Assessment {
    pub mode: Mode,
    pub allowed: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Version(pub u32, pub u32, pub u32);

impl Version {
    /// Finds the first `x.y.z` in a string such as
    /// `Partclone v0.3.50 http://partclone.org`.
    pub fn find_in(s: &str) -> Option<Self> {
        s.split(|c: char| !(c.is_ascii_digit() || c == '.'))
            .filter_map(|tok| {
                let mut it = tok.split('.').map(|p| p.parse::<u32>());
                match (it.next(), it.next(), it.next()) {
                    (Some(Ok(a)), Some(Ok(b)), Some(Ok(c))) => Some(Version(a, b, c)),
                    _ => None,
                }
            })
            .next()
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

// ---------------------------------------------------------- superbloque

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum ChecksumStatus {
    /// Checksum verified (crc32c, xxhash64, sha256 or blake2b).
    Valid,
    /// csum_type unknown to this build.
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
    pub features: FeatureSet,
}

// ------------------------------------------------------------- hashes

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgo {
    #[default]
    Blake3,
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Digest {
    pub algo: HashAlgo,
    pub hex: String,
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}",
            format!("{:?}", self.algo).to_lowercase(),
            self.hex
        )
    }
}

impl Digest {
    pub fn of_file(algo: HashAlgo, path: &Path) -> Result<Self> {
        use anyhow::Context;
        let mut f =
            std::fs::File::open(path).with_context(|| format!("abriendo {}", path.display()))?;
        let mut h = Hasher::new(algo);
        io::copy(&mut f, &mut h)?;
        Ok(h.finalize())
    }
}

/// Streaming hasher for any supported algorithm.
pub enum Hasher {
    Blake3(Box<blake3::Hasher>),
    Sha256(sha2::Sha256),
}

impl Hasher {
    pub fn new(algo: HashAlgo) -> Self {
        match algo {
            HashAlgo::Blake3 => Hasher::Blake3(Box::default()),
            HashAlgo::Sha256 => Hasher::Sha256(<sha2::Sha256 as sha2::Digest>::new()),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Blake3(h) => {
                h.update(data);
            }
            Hasher::Sha256(h) => sha2::Digest::update(h, data),
        }
    }

    pub fn finalize(self) -> Digest {
        match self {
            Hasher::Blake3(h) => Digest {
                algo: HashAlgo::Blake3,
                hex: h.finalize().to_hex().to_string(),
            },
            Hasher::Sha256(h) => Digest {
                algo: HashAlgo::Sha256,
                hex: sha2::Digest::finalize(h)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            },
        }
    }
}

impl Write for Hasher {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// --------------------------------------------- cifrado y troceado (previstos)

/// Cifrado del stream. Previsto en el esquema; aún no lo produce ningún modo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scheme", rename_all = "lowercase")]
pub enum Encryption {
    /// age (https://age-encryption.org), destinatarios X25519 o SSH.
    Age { recipients: Vec<String> },
}

/// Stream partido en trozos (p. ej. para FAT32 o subida por partes).
/// Previsto en el esquema; aún no lo produce ningún modo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunking {
    pub chunk_bytes: u64,
    pub parts: Vec<ChunkRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    pub path: PathBuf,
    pub bytes: u64,
    pub digest: Digest,
}

// ------------------------------------------------------------- streams

/// Un archivo de una cadena de copias: un stream completo y luego incrementales.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamRef {
    pub path: PathBuf,
    /// Hash del archivo tal como está en disco (comprimido y, si aplica, cifrado).
    pub digest: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<Encryption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunks: Option<Chunking>,
}

impl StreamRef {
    pub fn plain(path: PathBuf) -> Self {
        Self {
            path,
            digest: None,
            encryption: None,
            chunks: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Artifact {
    pub stream: PathBuf,
    pub snapshot: PathBuf,
    pub digest: Digest,
    pub compressed_bytes: u64,
    pub stream_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<Encryption>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunks: Option<Chunking>,
}

impl Artifact {
    pub fn stream_ref(&self) -> StreamRef {
        StreamRef {
            path: self.stream.clone(),
            digest: Some(self.digest.clone()),
            encryption: self.encryption.clone(),
            chunks: self.chunks.clone(),
        }
    }
}

// ------------------------------------------------- disposición del disco

/// Capas de bloque bajo el sistema de archivos (detect: LUKS, LVM…).
#[derive(Debug, Clone, Default, Serialize)]
pub struct BlockStack {
    /// De arriba (el dispositivo con el Btrfs) hacia abajo (el disco).
    pub layers: Vec<BlockLayer>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockLayer {
    pub kind: LayerKind,
    pub device: PathBuf,
    pub uuid: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerKind {
    Disk,
    Partition,
    Luks,
    LvmLv,
    Loop,
    Other,
}

/// Lo que un sistema necesita además de sus subvolúmenes para arrancar
/// (send: tabla de particiones, ESP, UUID).
#[derive(Debug, Clone, Default, Serialize)]
pub struct DiskLayout {
    pub fs_uuid: Option<String>,
    /// Copia de la tabla de particiones (`sgdisk --backup`).
    pub partition_table: Option<StreamRef>,
    /// Imagen de la partición EFI.
    pub esp: Option<StreamRef>,
    pub notes: Vec<String>,
}

/// Datos propios de una imagen sector a sector (modo raw).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawImage {
    /// Dispositivo (o archivo) leído entero.
    pub device: PathBuf,
    pub size_bytes: u64,
    /// Hash de los bytes del dispositivo tal cual, sin comprimir: una
    /// restauración es exacta si reproduce este mismo hash.
    pub content_digest: Digest,
}

// ---------------------------------------------------------- verificación

#[derive(Debug, Clone, Default, Serialize)]
pub struct Comparison {
    pub entries: usize,
    pub files: usize,
    pub bytes: u64,
    /// First differences found (capped at `MAX_DIFFS`).
    pub differences: Vec<String>,
    pub total_differences: usize,
}

impl Comparison {
    pub fn identical(&self) -> bool {
        self.total_differences == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
pub struct Step {
    pub name: &'static str,
    pub status: StepStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Every step passed.
    Valid,
    /// Nothing failed, but some steps were skipped.
    Reduced,
    Invalid,
}

#[derive(Debug, Clone, Serialize)]
pub struct Verification {
    pub verdict: Verdict,
    pub steps: Vec<Step>,
    pub comparison: Option<Comparison>,
}

// ------------------------------------------------------------- informe

/// Versión del esquema del informe. Súbela con cualquier cambio
/// incompatible y documenta la migración en `report`.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool: &'static str,
    pub version: &'static str,
    pub started: DateTime<Local>,
    pub finished: DateTime<Local>,
    pub source: PathBuf,
    pub device: Option<PathBuf>,
    pub block_stack: Option<BlockStack>,
    pub superblock: Option<Superblock>,
    pub modes: Vec<Assessment>,
    pub mode: Mode,
    pub hash_algo: HashAlgo,
    pub artifact: Option<Artifact>,
    pub layout: Option<DiskLayout>,
    /// Solo en modo raw.
    pub raw: Option<RawImage>,
    /// Informe de la copia sobre la que esta es incremental.
    pub parent_report: Option<PathBuf>,
    /// Streams a restaurar en orden para obtener esta copia, la base primero.
    pub chain: Vec<StreamRef>,
    pub verification: Option<Verification>,
    pub commands: Vec<CommandRecord>,
    /// Avisos que no impiden la copia (p. ej. copias del superbloque que
    /// discrepan, capas de bloque que no se pudieron leer).
    pub warnings: Vec<String>,
    pub error: Option<String>,
    /// Firma del informe sin este campo (report).
    pub signature: Option<Signature>,
}

impl Report {
    pub fn verdict(&self) -> Verdict {
        match (&self.error, &self.verification) {
            (None, Some(v)) => v.verdict,
            _ => Verdict::Invalid,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signature {
    /// Siempre "ed25519" por ahora.
    pub algo: String,
    pub public_key: String,
    pub value: String,
}

// -------------------------------------------------------- modos de copia

pub struct BackupRequest<'a> {
    pub source: &'a Path,
    pub dest_dir: &'a Path,
    /// Nombre único de esta copia (sin extensión).
    pub name: &'a str,
    pub snapshot_dir: Option<&'a Path>,
    /// Snapshot de la copia anterior, para una incremental.
    pub parent: Option<&'a Path>,
    pub zstd_level: i32,
    pub hash: HashAlgo,
}

/// Un modo de copia (send hoy; partclone y sector a sector después).
/// Qué modo es seguro lo decide `detect::modes::assess`, no el propio modo.
pub trait BackupMode {
    fn mode(&self) -> Mode;
    fn backup(&self, s: &mut Session, req: &BackupRequest) -> Result<Artifact>;
    /// Restaura la cadena en `target` y devuelve lo restaurado.
    fn restore(&self, s: &mut Session, chain: &[StreamRef], target: &Path) -> Result<PathBuf>;
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
