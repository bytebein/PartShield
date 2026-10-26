//! The JSON report written next to every backup.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use serde::Serialize;

use crate::cmd::CommandRecord;
use crate::modes::{Assessment, Mode};
use crate::send::{Artifact, StreamRef};
use crate::superblock::Superblock;
use crate::verify::Verification;

#[derive(Debug, Serialize)]
pub struct Report {
    pub tool: &'static str,
    pub version: &'static str,
    pub started: DateTime<Local>,
    pub finished: DateTime<Local>,
    pub source: PathBuf,
    pub device: Option<PathBuf>,
    pub superblock: Option<Superblock>,
    pub modes: Vec<Assessment>,
    pub mode: Mode,
    pub artifact: Option<Artifact>,
    /// Report of the backup this one is incremental to.
    pub parent_report: Option<PathBuf>,
    /// Streams to restore in order to get this backup, base first.
    pub chain: Vec<StreamRef>,
    pub verification: Option<Verification>,
    pub commands: Vec<CommandRecord>,
    pub error: Option<String>,
}

impl Report {
    pub fn write_json(&self, path: &Path) -> Result<()> {
        use std::io::Write;
        let json = serde_json::to_string_pretty(self)?;
        // Never overwrite a report: it is the only record of that backup.
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut f| f.write_all((json + "\n").as_bytes()))
            .with_context(|| format!("escribiendo {}", path.display()))
    }
}

/// What an incremental backup needs from the previous one.
#[derive(Debug, Clone)]
pub struct PriorBackup {
    pub snapshot: PathBuf,
    pub chain: Vec<StreamRef>,
    pub valid: bool,
}

/// Reads the chain recorded in a report written by `backup`.
pub fn load_prior(path: &Path) -> Result<PriorBackup> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("leyendo {}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("{} no es un informe válido", path.display()))?;
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
