//! The JSON report written next to every backup. The schema itself
//! (`types::Report`, `SCHEMA_VERSION`) is shared and owned by the lead.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::types::{Report, StreamRef};

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
