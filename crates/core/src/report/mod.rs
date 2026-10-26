//! El informe que se escribe junto a cada copia: JSON para máquinas
//! (`*.report.json`), HTML para personas (`*.report.html`) y firma ed25519.
//! El esquema (`types::Report`, `SCHEMA_VERSION`) es compartido y del lead;
//! aquí viven su descripción (`schema-v1.json`), la migración de informes
//! antiguos, el HTML y la firma.
//!
//! Ningún informe se sobrescribe nunca y todos se escriben de forma atómica
//! (ver [`atomic`]).

pub mod atomic;
pub mod html;
pub mod schema;
pub mod sign;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::types::{Report, StreamRef};

pub use html::{render_html, write_html};
pub use schema::{load_report_value, SCHEMA_V1};
pub use sign::{load_or_create_key, sign, verify_signature, SigningKey, VerifyingKey};

impl Report {
    /// Escribe el informe en JSON. Nunca sobrescribe; atómico.
    pub fn write_json(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)? + "\n";
        atomic::write_new(path, json.as_bytes(), 0o644)
    }
}

/// What an incremental backup needs from the previous one.
#[derive(Debug, Clone)]
pub struct PriorBackup {
    pub snapshot: PathBuf,
    pub chain: Vec<StreamRef>,
    pub valid: bool,
}

/// Reads the chain recorded in a report written by `backup` (any schema
/// version this build understands).
pub fn load_prior(path: &Path) -> Result<PriorBackup> {
    let v = load_report_value(path)?;
    let snapshot = v["artifact"]["snapshot"]
        .as_str()
        .map(PathBuf::from)
        .with_context(|| format!("{} no tiene snapshot", path.display()))?;
    let mut chain: Vec<StreamRef> = serde_json::from_value(v["chain"].clone())
        .with_context(|| format!("{} no tiene cadena de streams", path.display()))?;
    // A backup disk mounted elsewhere: look for the streams next to the report.
    let dir = path.parent().unwrap_or(Path::new("."));
    for link in &mut chain {
        if !link.path.exists() {
            if let Some(name) = link.path.file_name() {
                link.path = dir.join(name);
            }
        }
    }
    if chain.is_empty() {
        anyhow::bail!("{} tiene la cadena vacía", path.display());
    }
    let valid = v["error"].is_null() && v["verification"]["verdict"] == "valid";
    Ok(PriorBackup {
        snapshot,
        chain,
        valid,
    })
}

/// Informe y clave de ejemplo para los tests del módulo.
#[cfg(test)]
pub(crate) mod sample {
    use std::path::PathBuf;

    use chrono::{Local, TimeZone};

    use super::SigningKey;
    use crate::cmd::CommandRecord;
    use crate::types::*;

    pub fn key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    pub fn report() -> Report {
        let started = Local.with_ymd_and_hms(2026, 10, 26, 10, 0, 0).unwrap();
        let digest = Digest {
            algo: HashAlgo::Blake3,
            hex: "ab".repeat(32),
        };
        let artifact = Artifact {
            stream: "/copias/home-2.btrfs.zst".into(),
            snapshot: "/home/.partshield-home-2".into(),
            digest: digest.clone(),
            compressed_bytes: 1536,
            stream_bytes: 4 << 20,
            encryption: None,
            chunks: None,
        };
        Report {
            schema_version: SCHEMA_VERSION,
            tool: "partshield",
            version: "0.1.0",
            started,
            finished: started + chrono::Duration::seconds(42),
            source: PathBuf::from("/home/<raro> & \"cía\""),
            device: Some("/dev/loop0".into()),
            block_stack: Some(BlockStack {
                layers: vec![
                    BlockLayer {
                        kind: LayerKind::Loop,
                        device: "/dev/loop0".into(),
                        uuid: None,
                        detail: Some("archivo /tmp/x.img".into()),
                    },
                    BlockLayer {
                        kind: LayerKind::Partition,
                        device: "/dev/loop0p1".into(),
                        uuid: Some("1234-ABCD".into()),
                        detail: None,
                    },
                ],
            }),
            superblock: Some(Superblock {
                fsid: "0f1e2d3c-0000-4000-8000-000000000000".into(),
                label: "datos".into(),
                generation: 9,
                root: 1,
                chunk_root: 2,
                chunk_root_level: 0,
                total_bytes: 1 << 30,
                bytes_used: 5 << 20,
                num_devices: 1,
                sectorsize: 4096,
                nodesize: 16384,
                csum_type: 0,
                checksum: ChecksumStatus::Valid,
                features: FeatureSet {
                    compat: 0,
                    compat_ro: CompatRo(0xb),
                    incompat: Incompat(0x341),
                },
            }),
            modes: vec![
                Assessment {
                    mode: Mode::Send,
                    allowed: true,
                    reasons: vec!["nivel de archivo".into()],
                },
                Assessment {
                    mode: Mode::Partclone,
                    allowed: false,
                    reasons: vec!["partclone < 0.3.50".into()],
                },
            ],
            mode: Mode::Send,
            hash_algo: HashAlgo::Blake3,
            artifact: Some(artifact.clone()),
            layout: Some(DiskLayout {
                fs_uuid: Some("0f1e2d3c".into()),
                partition_table: Some(StreamRef::plain("/copias/gpt.bin".into())),
                esp: None,
                notes: vec!["sin ESP".into()],
            }),
            raw: None,
            parent_report: Some("/copias/home-1.report.json".into()),
            chain: vec![
                StreamRef {
                    path: "/copias/home-1.btrfs.zst".into(),
                    digest: Some(digest),
                    encryption: None,
                    chunks: None,
                },
                artifact.stream_ref(),
            ],
            verification: Some(Verification {
                verdict: Verdict::Valid,
                steps: vec![
                    Step {
                        name: "hash",
                        status: StepStatus::Passed,
                        detail: "<script>alert(1)</script>".into(),
                    },
                    Step {
                        name: "montaje",
                        status: StepStatus::Skipped,
                        detail: "a & b".into(),
                    },
                ],
                comparison: Some(Comparison {
                    entries: 3,
                    files: 2,
                    bytes: 100,
                    differences: vec![],
                    total_differences: 0,
                }),
            }),
            commands: vec![CommandRecord {
                command: "echo 'a&b' > /dev/null".into(),
                exit_code: Some(0),
                duration_ms: 3,
            }],
            error: None,
            signature: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_prior_reads_v1_and_old_reports() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = dir.path().join("v1.report.json");
        sample::report().write_json(&v1).unwrap();
        let prior = load_prior(&v1).unwrap();
        assert!(prior.valid);
        assert_eq!(prior.chain.len(), 2);
        assert!(sample::report().write_json(&v1).is_err());

        let old = dir.path().join("v0.report.json");
        std::fs::write(
            &old,
            r#"{"tool":"partshield","artifact":{"stream":"/c/a.zst","snapshot":"/s",
               "blake3":"ff","compressed_bytes":1,"stream_bytes":1},
               "chain":[{"path":"/c/a.zst","blake3":"ff"}],"error":null,
               "verification":{"verdict":"valid","steps":[],"comparison":null}}"#,
        )
        .unwrap();
        let prior = load_prior(&old).unwrap();
        assert!(prior.valid);
        assert_eq!(prior.chain[0].digest.as_ref().unwrap().hex, "ff");
        // El stream no existe en su ruta: se busca junto al informe.
        assert_eq!(prior.chain[0].path, dir.path().join("a.zst"));
    }

    #[test]
    fn load_prior_refuses_a_newer_schema() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("futuro.report.json");
        let mut v = serde_json::to_value(sample::report()).unwrap();
        v["schema_version"] = serde_json::json!(99);
        std::fs::write(&p, v.to_string()).unwrap();
        let err = format!("{:#}", load_prior(&p).unwrap_err());
        assert!(err.contains("v99"), "{err}");
    }

    #[test]
    fn signed_report_written_to_disk_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let key = load_or_create_key(&dir.path().join("k")).unwrap();
        let mut r = sample::report();
        sign(&mut r, &key).unwrap();
        let p = dir.path().join("r.report.json");
        r.write_json(&p).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        verify_signature(&text, &key.verifying_key()).unwrap();
        write_html(&r, &dir.path().join("r.report.html")).unwrap();
    }
}
