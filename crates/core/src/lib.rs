//! Motor de PartShield: detección de features, copia y verificación.
//!
//! La interfaz gráfica y la CLI son clientes de esta librería; todo lo que
//! hace la GUI se puede repetir desde la terminal.

pub mod cmd;
pub mod compare;
pub mod features;
pub mod modes;
pub mod report;
pub mod send;
pub mod superblock;
pub mod verify;

use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::Local;

use cmd::{Cmd, Session};
use modes::{Mode, Version};
use report::Report;
use superblock::Superblock;
use verify::{Verdict, VerifyOptions};

pub struct BackupOptions<'a> {
    pub source: &'a Path,
    pub dest_dir: &'a Path,
    pub snapshot_dir: Option<&'a Path>,
    pub scratch_dir: Option<&'a Path>,
    pub keep_snapshot: bool,
    pub zstd_level: i32,
}

/// Installed partclone.btrfs version, if any.
pub fn partclone_version(s: &mut Session) -> Option<Version> {
    let out = s
        .run_unchecked(&Cmd::new("partclone.btrfs").arg("--version"))
        .ok()?;
    Version::find_in(&out.stdout).or_else(|| Version::find_in(&out.stderr))
}

/// Snapshot → send → restore-and-verify, always producing a report.
///
/// The returned report's verification verdict is the only success signal:
/// an `Err` here means the report itself could not be produced.
pub fn backup(s: &mut Session, opts: &BackupOptions) -> Result<(Report, PathBuf)> {
    let started = Local::now();
    let name = format!(
        "{}-{}",
        base_name(opts.source),
        started.format("%Y%m%d-%H%M%S")
    );
    let report_path = opts.dest_dir.join(format!("{name}.report.json"));
    std::fs::create_dir_all(opts.dest_dir)?;

    let mut report = Report {
        tool: "partshield",
        version: env!("CARGO_PKG_VERSION"),
        started,
        finished: started,
        source: opts.source.to_path_buf(),
        device: None,
        superblock: None,
        modes: Vec::new(),
        mode: Mode::Send,
        artifact: None,
        verification: None,
        commands: Vec::new(),
        error: None,
    };

    if let Err(e) = run_backup(s, opts, &name, &mut report) {
        report.error = Some(format!("{e:#}"));
    }
    report.finished = Local::now();
    report.commands = std::mem::take(&mut s.records);
    report.write_json(&report_path)?;
    Ok((report, report_path))
}

fn run_backup(
    s: &mut Session,
    opts: &BackupOptions,
    name: &str,
    report: &mut Report,
) -> Result<()> {
    let device = send::backing_device(s, opts.source)?;
    let sb = Superblock::read_from(&device)?;
    report.modes = modes::assess(&sb.features, partclone_version(s));
    let scratch_size = sb.bytes_used.saturating_mul(2).max(1 << 30);
    report.device = Some(device);
    report.superblock = Some(sb);

    let artifact = send::send(
        s,
        &send::SendOptions {
            source: opts.source,
            dest_dir: opts.dest_dir,
            snapshot_dir: opts.snapshot_dir,
            name,
            zstd_level: opts.zstd_level,
        },
    )?;
    report.artifact = Some(artifact.clone());

    let verification = verify::verify(
        s,
        &VerifyOptions {
            stream: &artifact.stream,
            expected_blake3: Some(&artifact.blake3),
            reference: Some(&artifact.snapshot),
            scratch_dir: opts.scratch_dir.unwrap_or(opts.dest_dir),
            scratch_size,
        },
    );

    if !opts.keep_snapshot {
        send::delete_subvolume(s, &artifact.snapshot)?;
    }
    report.verification = Some(verification?);
    Ok(())
}

impl Report {
    pub fn verdict(&self) -> Verdict {
        match (&self.error, &self.verification) {
            (None, Some(v)) => v.verdict,
            _ => Verdict::Invalid,
        }
    }
}

fn base_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "raiz".to_string())
}
