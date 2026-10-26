//! Arnés de punta a punta: origen → `backup` → `load_prior` → `restore`
//! sobre otro Btrfs → desmontar → **montar la copia restaurada** →
//! `btrfs check` → comparar con el origen. Es la puerta de la Fase 0
//! aplicada a cada caso de contenido.

use std::path::{Path, PathBuf};

use partshield_core::cmd::Session;
use partshield_core::report::{load_prior, PriorBackup};
use partshield_core::send::restore::{restore, RestoreOptions, Restored};
use partshield_core::types::{CompatRo, HashAlgo, Mode, Report, Verdict};
use partshield_core::verify::compare::compare_trees;
use partshield_core::{backup, BackupOptions};

use super::{assert_same_tree, FsBuilder, TestFs, Tree};

/// One finished round trip. Field order is drop order: file systems are
/// unmounted before their parent tempdir goes away.
pub struct RoundTrip {
    pub source_fs: TestFs,
    pub target_fs: TestFs,
    /// Subvolume that was backed up, on `source_fs`.
    pub source: PathBuf,
    /// The restored writable snapshot, mounted on its own with `subvol=`.
    pub mounted_copy: PathBuf,
    pub report: Report,
    pub report_path: PathBuf,
    pub prior: PriorBackup,
    pub restored: Restored,
    pub tree: Tree,
    pub tmp: tempfile::TempDir,
}

pub struct Options {
    pub source_size: u64,
    pub target_size: u64,
    /// Relative paths left out of the strict comparison.
    pub exclude: Vec<&'static str>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            source_size: 2 << 30,
            target_size: 2 << 30,
            exclude: Vec::new(),
        }
    }
}

pub fn tempdir(name: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("partshield-e2e-{name}-"))
        .tempdir()
        .expect("tempdir")
}

pub fn backup_opts<'a>(
    source: &'a Path,
    snapshots: &'a Path,
    dest: &'a Path,
    scratch: &'a Path,
    parent: Option<&'a Path>,
) -> BackupOptions<'a> {
    BackupOptions {
        source,
        dest_dir: dest,
        snapshot_dir: Some(snapshots),
        scratch_dir: Some(scratch),
        keep_snapshot: true,
        zstd_level: 3,
        parent_report: parent,
        hash: HashAlgo::Blake3,
    }
}

/// Backs up a `datos` subvolume filled by `fill`, restores it onto a new
/// Btrfs and mounts the restored copy; panics on any difference.
pub fn round_trip(name: &str, opts: Options, fill: impl FnOnce(&Path, &TestFs)) -> RoundTrip {
    let tmp = tempdir(name);
    let source_fs = FsBuilder::new()
        .size(opts.source_size)
        .label("origen")
        .build_in(tmp.path());
    let source = source_fs.top.join("datos");
    super::sh(
        "btrfs",
        &["subvolume".as_ref(), "create".as_ref(), source.as_os_str()],
    );
    fill(&source, &source_fs);
    source_fs.sync();

    let dest = tmp.path().join("copias");
    let scratch = tmp.path().join("scratch");
    let (report, report_path) = backup(
        &mut Session::new(false),
        &backup_opts(&source, &source_fs.top, &dest, &scratch, None),
    )
    .expect("backup produce un informe");
    assert_backup_valid(&report);

    let prior = load_prior(&report_path).expect("load_prior");
    assert!(prior.valid, "load_prior no ve válida una copia válida");
    assert_eq!(prior.chain.len(), 1);

    let mut target_fs = FsBuilder::new()
        .size(opts.target_size)
        .label("destino")
        .build_in(tmp.path());
    let restored = restore(
        &mut Session::new(false),
        &RestoreOptions {
            streams: &prior.chain,
            target: &target_fs.top,
            writable_name: Some("datos"),
        },
    )
    .expect("restore");
    assert_eq!(
        restored.writable.as_deref(),
        Some(target_fs.top.join("datos").as_path())
    );

    // Puerta de la Fase 0: la copia restaurada se desmonta, pasa
    // btrfs check y se monta por sí sola antes de compararla.
    target_fs.unmount_all();
    let check = target_fs.check();
    assert!(
        check.status.success(),
        "btrfs check del destino restaurado: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    let mounted_copy = tmp.path().join("copia-montada");
    target_fs.mount_subvol("datos", &mounted_copy, ",ro");

    let c = compare_trees(&source, &mounted_copy).expect("compare_trees");
    assert!(c.identical(), "compare_trees: {:?}", c.differences);
    let tree = assert_same_tree(&source, &mounted_copy, &opts.exclude);

    RoundTrip {
        source_fs,
        target_fs,
        source,
        mounted_copy,
        report,
        report_path,
        prior,
        restored,
        tree,
        tmp,
    }
}

/// The checks every good backup report must pass.
pub fn assert_backup_valid(report: &Report) {
    let v = report.verification.as_ref();
    assert_eq!(
        report.verdict(),
        Verdict::Valid,
        "error: {:?}\npasos: {:#?}\ndiferencias: {:?}",
        report.error,
        v.map(|v| &v.steps),
        v.and_then(|v| v.comparison.as_ref())
            .map(|c| &c.differences)
    );
    let sb = report
        .superblock
        .as_ref()
        .expect("superbloque en el informe");
    assert!(
        sb.features.compat_ro.contains(CompatRo::BLOCK_GROUP_TREE),
        "el origen debía tener BLOCK_GROUP_TREE"
    );
    let send = report.modes.iter().find(|m| m.mode == Mode::Send).unwrap();
    assert!(send.allowed);
    assert!(report.artifact.is_some());
}
