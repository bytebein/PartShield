//! Motor de PartShield: detección de features, copia y verificación.
//!
//! La interfaz gráfica y la CLI son clientes de esta librería; todo lo que
//! hace la GUI se puede repetir desde la terminal.

//!
//! Propiedad de cada módulo (equipo de la Fase 0):
//! - `types`, `cmd`, `lib`: lead (tipos compartidos, orquestación)
//! - `detect`: superbloque, features, modos seguros, LUKS/LVM
//! - `raw`: imagen sector a sector (lead)
//! - `send`: snapshots, send/receive, zstd, incrementales, disposición del disco
//! - `verify`: restauración de prueba y comprobaciones
//! - `report`: JSON, HTML, firma
//! - `tests/`: fixtures y arnés de regresión

pub mod cmd;
pub mod detect;
pub mod raw;
pub mod report;
pub mod send;
pub mod types;
pub mod verify;

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use chrono::Local;

use cmd::{Cmd, Session};
use detect::{modes, SuperblockExt};
use send::SendMode;
use types::{BackupMode, BackupRequest, HashAlgo, Report, Superblock, Version, SCHEMA_VERSION};
use verify::VerifyOptions;

pub struct BackupOptions<'a> {
    pub source: &'a Path,
    pub dest_dir: &'a Path,
    pub snapshot_dir: Option<&'a Path>,
    pub scratch_dir: Option<&'a Path>,
    pub keep_snapshot: bool,
    pub zstd_level: i32,
    /// Report of a previous valid backup whose snapshot was kept; makes
    /// this backup incremental to it.
    pub parent_report: Option<&'a Path>,
    pub hash: HashAlgo,
    /// Clave ed25519 con la que firmar el informe (se crea si no existe).
    pub sign_key: Option<&'a Path>,
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
    std::fs::create_dir_all(opts.dest_dir)?;
    let dest_dir = opts.dest_dir.canonicalize()?;
    let opts = &BackupOptions {
        dest_dir: &dest_dir,
        ..*opts
    };
    let stem = format!(
        "{}-{}",
        base_name(opts.source),
        started.format("%Y%m%d-%H%M%S")
    );
    let name = unique_name(
        &stem,
        opts.dest_dir,
        opts.snapshot_dir.unwrap_or(opts.source),
    );
    let report_path = opts.dest_dir.join(format!("{name}.report.json"));

    let mode = SendMode;
    let mut report = Report {
        schema_version: SCHEMA_VERSION,
        tool: "partshield",
        version: env!("CARGO_PKG_VERSION"),
        started,
        finished: started,
        source: opts.source.to_path_buf(),
        device: None,
        block_stack: None,
        superblock: None,
        modes: Vec::new(),
        mode: mode.mode(),
        hash_algo: opts.hash,
        artifact: None,
        layout: None,
        raw: None,
        parent_report: opts.parent_report.map(Path::to_path_buf),
        chain: Vec::new(),
        verification: None,
        commands: Vec::new(),
        error: None,
        signature: None,
    };

    if let Err(e) = run_backup(s, &mode, opts, &name, &mut report) {
        report.error = Some(format!("{e:#}"));
    }
    report.finished = Local::now();
    report.commands = std::mem::take(&mut s.records);
    write_report(&mut report, &report_path, opts.sign_key)?;
    Ok((report, report_path))
}

fn run_backup(
    s: &mut Session,
    mode: &dyn BackupMode,
    opts: &BackupOptions,
    name: &str,
    report: &mut Report,
) -> Result<()> {
    let prior = match opts.parent_report {
        None => None,
        Some(p) => {
            let prior = report::load_prior(p)?;
            if !prior.valid {
                bail!(
                    "la copia de {} no es válida; no se encadena una incremental a ella",
                    p.display()
                );
            }
            if !prior.snapshot.exists() {
                bail!(
                    "el snapshot {} ya no existe; la copia base debe hacerse con --keep-snapshot",
                    prior.snapshot.display()
                );
            }
            Some(prior)
        }
    };

    let device = send::backing_device(s, opts.source)?;
    let sb = Superblock::read_from(&device)?;
    report.modes = modes::assess(&sb.features, partclone_version(s));
    let scratch_size = sb.bytes_used.saturating_mul(2).max(1 << 30);
    report.device = Some(device);
    report.superblock = Some(sb);

    let artifact = mode.backup(
        s,
        &BackupRequest {
            source: opts.source,
            dest_dir: opts.dest_dir,
            name,
            snapshot_dir: opts.snapshot_dir,
            parent: prior.as_ref().map(|p| p.snapshot.as_path()),
            zstd_level: opts.zstd_level,
            hash: opts.hash,
        },
    )?;
    report.artifact = Some(artifact.clone());
    report.chain = prior.map(|p| p.chain).unwrap_or_default();
    report.chain.push(artifact.stream_ref());

    let verification = verify::verify(
        s,
        &VerifyOptions {
            streams: &report.chain,
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

pub struct RawOptions<'a> {
    /// Dispositivo o archivo de imagen a copiar entero. No puede estar
    /// montado en lectura-escritura.
    pub device: &'a Path,
    pub dest_dir: &'a Path,
    pub scratch_dir: Option<&'a Path>,
    pub zstd_level: i32,
    pub hash: HashAlgo,
    pub sign_key: Option<&'a Path>,
}

/// Imagen sector a sector → verificación, siempre con informe.
pub fn backup_raw(s: &mut Session, opts: &RawOptions) -> Result<(Report, PathBuf)> {
    let started = Local::now();
    std::fs::create_dir_all(opts.dest_dir)?;
    let dest_dir = opts.dest_dir.canonicalize()?;
    let stem = format!(
        "{}-{}",
        base_name(opts.device),
        started.format("%Y%m%d-%H%M%S")
    );
    let name = unique_name(&stem, &dest_dir, &dest_dir);
    let report_path = dest_dir.join(format!("{name}.report.json"));

    let mut report = Report {
        schema_version: SCHEMA_VERSION,
        tool: "partshield",
        version: env!("CARGO_PKG_VERSION"),
        started,
        finished: started,
        source: opts.device.to_path_buf(),
        device: Some(opts.device.to_path_buf()),
        block_stack: None,
        superblock: None,
        modes: Vec::new(),
        mode: types::Mode::Raw,
        hash_algo: opts.hash,
        artifact: None,
        layout: None,
        raw: None,
        parent_report: None,
        chain: Vec::new(),
        verification: None,
        commands: Vec::new(),
        error: None,
        signature: None,
    };

    let run = |s: &mut Session, report: &mut Report| -> Result<()> {
        // Si es Btrfs, se registra lo detectado; la imagen raw vale igual si no lo es.
        if let Ok(sb) = Superblock::read_from(opts.device) {
            report.modes = modes::assess(&sb.features, partclone_version(s));
            report.superblock = Some(sb);
        }
        let (artifact, image) = raw::backup(
            s,
            &raw::RawBackupOptions {
                device: opts.device,
                dest_dir: &dest_dir,
                name: &name,
                zstd_level: opts.zstd_level,
                hash: opts.hash,
            },
        )?;
        report.chain = vec![artifact.stream_ref()];
        report.artifact = Some(artifact);
        report.raw = Some(image.clone());
        report.verification = Some(raw::verify(
            s,
            &report.chain[0],
            &image,
            opts.scratch_dir.unwrap_or(&dest_dir),
        )?);
        Ok(())
    };
    if let Err(e) = run(s, &mut report) {
        report.error = Some(format!("{e:#}"));
    }
    report.finished = Local::now();
    report.commands = std::mem::take(&mut s.records);
    write_report(&mut report, &report_path, opts.sign_key)?;
    Ok((report, report_path))
}

/// Firma (si hay clave) y escribe `X.report.json` y `X.report.html`.
///
/// Si la firma falla, el informe se escribe igualmente sin firmar (es el
/// único registro de una copia ya hecha) y después se devuelve el error.
fn write_report(report: &mut Report, path: &Path, sign_key: Option<&Path>) -> Result<()> {
    let signed = match sign_key {
        None => Ok(()),
        Some(k) => report::load_or_create_key(k).and_then(|key| report::sign(report, &key)),
    };
    report.write_json(path)?;
    report::write_html(report, &path.with_extension("html"))?;
    signed.map_err(|e| e.context("la copia está hecha, pero el informe ha quedado sin firmar"))
}

/// First of `stem`, `stem-1`, `stem-2`… that no earlier backup used, so a
/// second backup in the same second never touches the first one's files.
fn unique_name(stem: &str, dest_dir: &Path, snapshot_dir: &Path) -> String {
    (0..)
        .map(|i| match i {
            0 => stem.to_string(),
            i => format!("{stem}-{i}"),
        })
        .find(|n| {
            let taken = [
                dest_dir.join(format!("{n}.report.json")),
                dest_dir.join(format!("{n}.report.html")),
                dest_dir.join(format!("{n}.btrfs.zst")),
                dest_dir.join(format!("{n}.raw.zst")),
                snapshot_dir.join(format!(".partshield-{n}")),
            ];
            !taken.iter().any(|p| p.exists())
        })
        .expect("an unused name exists")
}

fn base_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "raiz".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_name_skips_every_taken_file() {
        let dest = tempfile::tempdir().unwrap();
        let snaps = tempfile::tempdir().unwrap();
        assert_eq!(unique_name("home-1", dest.path(), snaps.path()), "home-1");
        std::fs::write(dest.path().join("home-1.report.json"), "").unwrap();
        std::fs::write(dest.path().join("home-1-1.btrfs.zst"), "").unwrap();
        std::fs::create_dir(snaps.path().join(".partshield-home-1-2")).unwrap();
        assert_eq!(unique_name("home-1", dest.path(), snaps.path()), "home-1-3");
    }
}
