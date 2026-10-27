//! Control negativo y positivo con partclone sobre un Btrfs con
//! BLOCK_GROUP_TREE y chunk tree de varios niveles (partclone #303).
//!
//! - `chunk_tree_multinivel_con_send`: PartShield (send) restaura y monta
//!   ese Btrfs. Solo necesita `PARTSHIELD_E2E=1`.
//! - `control_negativo_partclone_0347`: con `PARTCLONE_0347=<partclone.btrfs>`
//!   la imagen de partclone 0.3.47 restaurada no monta (`cannot read chunk
//!   root`), `detect::modes::assess` no permite partclone para ese Btrfs, y
//!   la copia por send del mismo Btrfs sí se restaura y monta.
//! - `control_positivo_partclone_0350`: con `PARTCLONE_0350=<partclone.btrfs>`
//!   la imagen restaurada monta y es igual al origen, y `assess` lo permite.
//!
//! Los binarios se compilan con `tests/partclone-control.sh`:
//!   tests/partclone-control.sh build 0.3.47 pattern
//!   tests/partclone-control.sh build 0.3.50
//!   PARTCLONE_0347=/tmp/partclone-bin/0.3.47-pattern/sbin/partclone.btrfs \
//!   PARTCLONE_0350=/tmp/partclone-bin/0.3.50/sbin/partclone.btrfs \
//!   PARTSHIELD_SANDBOX=1 PARTSHIELD_E2E=1 cargo test --test partclone_control
//!
//! El fallo de 0.3.47 es una variable sin inicializar (`size` en
//! `dump_start_leaf`): con `-O2` normal la pila suele contener el valor
//! bueno por casualidad y la imagen sale bien. La variante `pattern`
//! (`-ftrivial-auto-var-init=pattern`) fija esa basura y lo hace
//! reproducible; ver el script.

mod common;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use common::harness::{assert_backup_valid, backup_opts, tempdir};
use common::{e2e_enabled, multilevel_fs, run, sh, FsBuilder, RawLoop, TestFs};
use partshield_core::backup;
use partshield_core::cmd::Session;
use partshield_core::detect::modes::assess;
use partshield_core::report::load_prior;
use partshield_core::send::restore::{restore, RestoreOptions};
use partshield_core::types::{Assessment, CompatRo, Mode, Version};

fn partclone_bin(var: &str, how: &str) -> Option<PathBuf> {
    match std::env::var_os(var) {
        Some(p) if Path::new(&p).is_file() => Some(PathBuf::from(p)),
        Some(p) => panic!("{var}={} no existe", Path::new(&p).display()),
        None => {
            eprintln!(
                "omitido: define {var}=<ruta a partclone.btrfs> ({how}; \
                 compílalo con partshield/tests/partclone-control.sh)"
            );
            None
        }
    }
}

fn version_of(bin: &Path) -> Version {
    let out = run(bin.to_str().unwrap(), &["--version"]);
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    Version::find_in(&text).unwrap_or_else(|| panic!("sin versión en {text:?}"))
}

fn partclone_assessment(fs: &TestFs, v: Version) -> Assessment {
    let sb = fs.superblock();
    assert!(sb.features.compat_ro.contains(CompatRo::BLOCK_GROUP_TREE));
    assess(&sb.features, Some(v))
        .into_iter()
        .find(|a| a.mode == Mode::Partclone)
        .unwrap()
}

/// Copy of `datos` by PartShield (send), restored onto a new Btrfs,
/// remounted on its own and compared with the source.
fn partshield_round_trip(src: &TestFs, tmp: &Path) {
    let source = src.top.join("datos");
    let (report, report_path) = backup(
        &mut Session::new(false),
        &backup_opts(
            &source,
            &src.top,
            &tmp.join("copias"),
            &tmp.join("scratch"),
            None,
        ),
    )
    .unwrap();
    assert_backup_valid(&report);
    let prior = load_prior(&report_path).unwrap();
    let mut dst = FsBuilder::new().label("destino").build_in(tmp);
    restore(
        &mut Session::new(false),
        &RestoreOptions {
            streams: &prior.chain,
            target: &dst.top,
            writable_name: Some("datos"),
        },
    )
    .unwrap();
    dst.unmount_all();
    let check = dst.check();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let m = tmp.join("send-montada");
    dst.mount_subvol("datos", &m, ",ro");
    common::assert_same_tree(&source, &m, &[]);
    eprintln!("PartShield (send): restaurado, btrfs check limpio, montado e idéntico al origen");
}

struct PartcloneOutcome {
    check_ok: bool,
    check_text: String,
    mount_ok: bool,
    mount_text: String,
    /// Mounted copy (when it mounted), kept alive by `target`.
    mounted: Option<PathBuf>,
    target: RawLoop,
}

/// `partclone.btrfs -c` of the (unmounted) source, then `-r` onto a fresh
/// loop device, then `btrfs check` and `mount` of the result. The source
/// is detached before mounting, because the copy has the same fsid.
fn partclone_round_trip(bin: &Path, mut src: TestFs, tmp: &Path) -> PartcloneOutcome {
    src.unmount_all();
    let size = std::fs::metadata(&src.image).unwrap().len();
    let image = tmp.join("imagen.partclone");
    let pc = bin.to_str().unwrap();
    let dev = src.loopdev.clone();
    sh(
        pc,
        &[
            OsStr::new("-c"),
            OsStr::new("-q"),
            OsStr::new("-s"),
            dev.as_os_str(),
            OsStr::new("-o"),
            image.as_os_str(),
            OsStr::new("-L"),
            tmp.join("clone.log").as_os_str(),
        ],
    );
    drop(src);
    let mut target = RawLoop::new(tmp, size);
    sh(
        pc,
        &[
            OsStr::new("-r"),
            OsStr::new("-q"),
            OsStr::new("-s"),
            image.as_os_str(),
            OsStr::new("-o"),
            target.loopdev.as_os_str(),
            OsStr::new("-L"),
            tmp.join("restore.log").as_os_str(),
        ],
    );
    let check = run(
        "btrfs",
        &[
            OsStr::new("check"),
            OsStr::new("--readonly"),
            target.loopdev.as_os_str(),
        ],
    );
    let check_text = String::from_utf8_lossy(&check.stderr).to_string()
        + &String::from_utf8_lossy(&check.stdout);
    let (mount, at) = target.try_mount_ro();
    PartcloneOutcome {
        check_ok: check.status.success(),
        check_text,
        mount_ok: mount.status.success(),
        mount_text: String::from_utf8_lossy(&mount.stderr).to_string(),
        mounted: mount.status.success().then_some(at),
        target,
    }
}

#[test]
fn chunk_tree_multinivel_con_send() {
    if !e2e_enabled("chunk_tree_multinivel_con_send") {
        return;
    }
    let tmp = tempdir("multinivel");
    let src = multilevel_fs(tmp.path());
    partshield_round_trip(&src, tmp.path());
}

#[test]
fn control_negativo_partclone_0347() {
    if !e2e_enabled("control_negativo_partclone_0347") {
        return;
    }
    let Some(bin) = partclone_bin("PARTCLONE_0347", "control negativo") else {
        return;
    };
    let v = version_of(&bin);
    assert_eq!(v, Version(0, 3, 47), "{} no es 0.3.47", bin.display());

    let tmp = tempdir("pc0347");
    let src = multilevel_fs(tmp.path());

    // 1. PartShield no lo habría permitido.
    let a = partclone_assessment(&src, v);
    assert!(
        !a.allowed,
        "assess permite partclone 0.3.47 con BLOCK_GROUP_TREE"
    );
    assert!(
        a.reasons.iter().any(|r| r.contains("0.3.47")),
        "{:?}",
        a.reasons
    );
    eprintln!("assess(partclone 0.3.47): no permitido: {:?}", a.reasons);

    // 2. Y su copia por send del mismo Btrfs se restaura y monta.
    partshield_round_trip(&src, tmp.path());

    // 3. partclone 0.3.47 termina con éxito, pero su copia no monta.
    let out = partclone_round_trip(&bin, src, tmp.path());
    eprintln!("btrfs check:\n{}", out.check_text);
    eprintln!("mount: {}", out.mount_text);
    assert!(
        !out.check_ok && !out.mount_ok,
        "partclone 0.3.47 dio una copia buena: este binario no reproduce #303 \
         (¿compilado sin -ftrivial-auto-var-init=pattern?). check: {}",
        out.check_text
    );
    assert!(
        out.check_text.contains("cannot read chunk root"),
        "{}",
        out.check_text
    );
    drop(out.target);
}

#[test]
fn control_positivo_partclone_0350() {
    if !e2e_enabled("control_positivo_partclone_0350") {
        return;
    }
    let Some(bin) = partclone_bin("PARTCLONE_0350", "control positivo") else {
        return;
    };
    let v = version_of(&bin);
    assert!(v >= Version(0, 3, 50), "{} es {v}", bin.display());

    let tmp = tempdir("pc0350");
    let src = multilevel_fs(tmp.path());
    let a = partclone_assessment(&src, v);
    assert!(
        a.allowed,
        "assess no permite partclone {v}: {:?}",
        a.reasons
    );

    // Referencia: el contenido del origen, leído antes de desmontarlo.
    let reference = common::snapshot_tree(&src.top.join("datos"), &[]);
    let out = partclone_round_trip(&bin, src, tmp.path());
    assert!(out.check_ok, "btrfs check: {}", out.check_text);
    assert!(out.mount_ok, "mount: {}", out.mount_text);
    let copy = common::snapshot_tree(&out.mounted.as_ref().unwrap().join("datos"), &[]);
    let d = common::diff_trees(&reference, &copy);
    assert!(d.is_empty(), "{d:#?}");
    eprintln!("partclone {v}: restaurado, btrfs check limpio, montado e idéntico al origen");
}
