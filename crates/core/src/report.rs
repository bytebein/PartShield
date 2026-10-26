//! The JSON report written next to every backup.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use serde::Serialize;

use crate::cmd::CommandRecord;
use crate::modes::{Assessment, Mode};
use crate::send::Artifact;
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
    pub verification: Option<Verification>,
    pub commands: Vec<CommandRecord>,
    pub error: Option<String>,
}

impl Report {
    pub fn write_json(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json + "\n").with_context(|| format!("escribiendo {}", path.display()))
    }
}
