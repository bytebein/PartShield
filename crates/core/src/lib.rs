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
use send::multi::SubvolSpec;
use send::SendMode;
use types::{
    BackupMode, BackupRequest, HashAlgo, Report, SubvolArtifact, Superblock, Version,
    SCHEMA_VERSION,
};
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
    /// Varios subvolúmenes en una copia (`@`, `@home`…). Vacío: solo `source`.
    pub subvolumes: &'a [SubvolSpec<'a>],
    /// Guardar aparte tabla de particiones, ESP y UUID del sistema de archivos.
    pub capture_layout: bool,
    /// Disco que contiene el Btrfs, si no se puede deducir con lsblk.
    pub disk: Option<&'a Path>,
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
        subvolumes: Vec::new(),
        parent_report: opts.parent_report.map(Path::to_path_buf),
        chain: Vec::new(),
        verification: None,
        commands: Vec::new(),
        warnings: Vec::new(),
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
        // En una copia de varios subvolúmenes el padre se lee en run_multi.
        Some(_) if !opts.subvolumes.is_empty() => None,
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
    let sb = inspect_device(s, &device, report)?;
    let scratch_size = sb.bytes_used.saturating_mul(2).max(1 << 30);
    report.device = Some(device.clone());
    report.superblock = Some(sb);

    if opts.capture_layout {
        report.layout = Some(send::layout::capture_with(
            s,
            &send::layout::CaptureOptions {
                fs_device: &device,
                disk: opts.disk,
                dest_dir: opts.dest_dir,
                name,
                zstd_level: opts.zstd_level,
                hash: opts.hash,
            },
        )?);
    }
    if !opts.subvolumes.is_empty() {
        return run_multi(s, opts, name, scratch_size, report);
    }

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

/// Varios subvolúmenes: cada uno con su cadena, verificados uno a uno.
fn run_multi(
    s: &mut Session,
    opts: &BackupOptions,
    name: &str,
    scratch_size: u64,
    report: &mut Report,
) -> Result<()> {
    let previous = match opts.parent_report {
        None => Vec::new(),
        Some(p) => prior_subvolumes(p)?,
    };
    let items = send::multi::send_many(
        s,
        &send::multi::MultiSendOptions {
            subvolumes: opts.subvolumes,
            dest_dir: opts.dest_dir,
            snapshot_dir: opts.snapshot_dir,
            name,
            zstd_level: opts.zstd_level,
            hash: opts.hash,
            previous: &previous,
        },
    )?;
    report.subvolumes = items.clone();
    let verification = verify_subvolumes(
        s,
        &items,
        opts.scratch_dir.unwrap_or(opts.dest_dir),
        scratch_size,
    );
    if !opts.keep_snapshot {
        for it in &items {
            send::delete_subvolume(s, &it.artifact.snapshot)?;
        }
    }
    report.verification = Some(verification?);
    Ok(())
}

/// Subvolúmenes de una copia anterior válida, con los streams buscados junto
/// al informe si el disco de copias se montó en otra ruta.
pub fn prior_subvolumes(report_path: &Path) -> Result<Vec<SubvolArtifact>> {
    let v = report::load_report_value(report_path)?;
    let valid = v["error"].is_null() && v["verification"]["verdict"] == "valid";
    if !valid {
        bail!(
            "la copia de {} no es válida; no se encadena una incremental a ella",
            report_path.display()
        );
    }
    let mut items: Vec<SubvolArtifact> = serde_json::from_value(v["subvolumes"].clone())
        .ok()
        .filter(|i: &Vec<SubvolArtifact>| !i.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} no es una copia de varios subvolúmenes",
                report_path.display()
            )
        })?;
    let dir = report_path.parent().unwrap_or(Path::new("."));
    for it in &mut items {
        for link in &mut it.chain {
            if !link.path.exists() {
                if let Some(f) = link.path.file_name() {
                    link.path = dir.join(f);
                }
            }
        }
    }
    Ok(items)
}

/// Verifica cada subvolumen restaurando su cadena y comparándolo con su
/// snapshot. El resultado tiene los cinco pasos de siempre: cada paso toma
/// el peor estado de todos los subvolúmenes y junta sus detalles.
pub fn verify_subvolumes(
    s: &mut Session,
    items: &[SubvolArtifact],
    scratch_dir: &Path,
    scratch_size: u64,
) -> Result<types::Verification> {
    use types::{Step, StepStatus};
    let mut each = Vec::new();
    for it in items {
        let reference = it
            .artifact
            .snapshot
            .exists()
            .then_some(it.artifact.snapshot.as_path());
        let v = verify::verify(
            s,
            &VerifyOptions {
                streams: &it.chain,
                reference,
                scratch_dir,
                scratch_size,
            },
        )?;
        each.push((it.label.as_str(), v));
    }
    let steps: Vec<Step> = verify::STEPS
        .iter()
        .map(|&name| {
            let mine: Vec<(&str, &Step)> = each
                .iter()
                .filter_map(|(l, v)| v.steps.iter().find(|st| st.name == name).map(|st| (*l, st)))
                .collect();
            let status = if mine.len() != items.len()
                || mine.iter().any(|(_, st)| st.status == StepStatus::Failed)
            {
                StepStatus::Failed
            } else if mine.iter().any(|(_, st)| st.status == StepStatus::Skipped) {
                StepStatus::Skipped
            } else {
                StepStatus::Passed
            };
            let detail = mine
                .iter()
                .map(|(l, st)| format!("{l}: {}", st.detail))
                .collect::<Vec<_>>()
                .join(" | ");
            Step {
                name,
                status,
                detail,
            }
        })
        .collect();
    Ok(types::Verification {
        verdict: verify::verdict_of(&steps),
        steps,
        comparison: None,
    })
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
        subvolumes: Vec::new(),
        parent_report: None,
        chain: Vec::new(),
        verification: None,
        commands: Vec::new(),
        warnings: Vec::new(),
        error: None,
        signature: None,
    };

    let run = |s: &mut Session, report: &mut Report| -> Result<()> {
        // Si es Btrfs, se registra lo detectado; la imagen raw vale igual si no lo es.
        if Superblock::read_from(opts.device).is_ok() {
            let sb = inspect_device(s, opts.device, report)?;
            report.superblock = Some(sb);
        } else {
            report.block_stack = block_stack_or_warn(s, opts.device, report);
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

/// Superbloque (las tres copias), modos seguros según el kernel y capas
/// de bloque. Lo que no impide la copia queda en `report.warnings`.
fn inspect_device(s: &mut Session, device: &Path, report: &mut Report) -> Result<Superblock> {
    let copies = detect::read_all_copies(device)?;
    let sb = copies.primary().cloned().ok_or_else(|| {
        anyhow::anyhow!(
            "el superbloque primario de {} no es válido: {:?}",
            device.display(),
            copies.copies.first().map(|c| &c.status)
        )
    })?;
    report.warnings.extend(copies.discrepancies());
    report.modes = modes::assess_with_kernel(
        &sb.features,
        partclone_version(s),
        modes::KernelFeatures::from_sysfs().as_ref(),
    );
    report.block_stack = block_stack_or_warn(s, device, report);
    Ok(sb)
}

fn block_stack_or_warn(
    s: &mut Session,
    device: &Path,
    report: &mut Report,
) -> Option<types::BlockStack> {
    match detect::block_stack(s, device) {
        Ok(b) => Some(b),
        Err(e) => {
            report
                .warnings
                .push(format!("no se pudieron leer las capas de bloque: {e:#}"));
            None
        }
    }
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
            // Cualquier archivo de esa copia: informe, streams, tabla, ESP,
            // subvolúmenes (`<n>--<etiqueta>…`).
            let (dot, sub) = (format!("{n}."), format!("{n}--"));
            let in_dest = std::fs::read_dir(dest_dir)
                .into_iter()
                .flatten()
                .flatten()
                .any(|e| {
                    let f = e.file_name();
                    let f = f.to_string_lossy();
                    f.starts_with(&dot) || f.starts_with(&sub)
                });
            !in_dest && !snapshot_dir.join(format!(".partshield-{n}")).exists()
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
