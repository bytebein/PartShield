//! Copia de varios subvolúmenes (`@`, `@home`) de punta a punta: completa,
//! incremental sobre ella y restauración en otro Btrfs.
//!
//! `PARTSHIELD_SANDBOX=1 PARTSHIELD_E2E=1 cargo test --test multi_e2e` (root).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use partshield_core::cmd::Session;
use partshield_core::send::multi::{restore_many, SubvolSpec};
use partshield_core::types::{HashAlgo, StepStatus, Verdict};
use partshield_core::verify::compare::compare_trees;
use partshield_core::{backup, prior_subvolumes, verify_subvolumes, BackupOptions};

fn sh(program: &str, args: &[&str]) -> String {
    for a in args {
        assert!(
            !a.starts_with("/dev/") || a.starts_with("/dev/loop"),
            "solo loop devices: {a}"
        );
    }
    let out = Command::new(program).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

struct Fs {
    dev: String,
    mnt: PathBuf,
}

impl Fs {
    fn new(dir: &Path, name: &str) -> Self {
        let img = dir.join(format!("{name}.img"));
        fs::File::create(&img).unwrap().set_len(1 << 30).unwrap();
        let dev = sh("losetup", &["--find", "--show", img.to_str().unwrap()]);
        sh("mkfs.btrfs", &["-q", "-O", "block-group-tree", &dev]);
        let mnt = dir.join(format!("{name}-mnt"));
        fs::create_dir(&mnt).unwrap();
        sh(
            "mount",
            &["-o", "compress=zstd", &dev, mnt.to_str().unwrap()],
        );
        Fs { dev, mnt }
    }
}

impl Drop for Fs {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.mnt).status();
        let _ = Command::new("losetup")
            .arg("--detach")
            .arg(&self.dev)
            .status();
    }
}

fn opts<'a>(
    root: &'a Path,
    dest: &'a Path,
    scratch: &'a Path,
    subvolumes: &'a [SubvolSpec<'a>],
    parent: Option<&'a Path>,
) -> BackupOptions<'a> {
    BackupOptions {
        source: subvolumes[0].source,
        dest_dir: dest,
        snapshot_dir: Some(root),
        scratch_dir: Some(scratch),
        keep_snapshot: true,
        zstd_level: 3,
        parent_report: parent,
        hash: HashAlgo::Blake3,
        sign_key: None,
        subvolumes,
        capture_layout: false,
        disk: None,
    }
}

#[test]
fn two_subvolumes_full_incremental_and_restore() {
    if std::env::var_os("PARTSHIELD_E2E").is_none() {
        eprintln!("omitido: define PARTSHIELD_E2E=1 (necesita root y loop devices)");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let origin = Fs::new(tmp.path(), "origen");
    let (root_sv, home_sv) = (origin.mnt.join("@"), origin.mnt.join("@home"));
    for sv in [&root_sv, &home_sv] {
        sh("btrfs", &["subvolume", "create", sv.to_str().unwrap()]);
    }
    fs::create_dir_all(root_sv.join("etc")).unwrap();
    fs::write(root_sv.join("etc/hostname"), "casa\n").unwrap();
    fs::create_dir_all(home_sv.join("dani")).unwrap();
    fs::write(home_sv.join("dani/notas.txt"), "primera\n").unwrap();

    let specs = [
        SubvolSpec {
            label: "@",
            source: &root_sv,
        },
        SubvolSpec {
            label: "@home",
            source: &home_sv,
        },
    ];
    let dest = tmp.path().join("copias");

    // 1. Copia completa de los dos.
    let (full, full_path) = backup(
        &mut Session::new(false),
        &opts(&origin.mnt, &dest, tmp.path(), &specs, None),
    )
    .unwrap();
    let v = full.verification.as_ref().unwrap();
    assert_eq!(
        full.verdict(),
        Verdict::Valid,
        "{:?} {:#?}",
        full.error,
        v.steps
    );
    assert_eq!(full.subvolumes.len(), 2);
    assert!(full.subvolumes.iter().all(|s| s.parent.is_none()));
    let muestra = v.steps.iter().find(|s| s.name == "muestra").unwrap();
    assert!(muestra.detail.contains("@:") && muestra.detail.contains("@home:"));

    // 2. Incremental: solo cambia @home.
    fs::write(home_sv.join("dani/notas.txt"), "segunda\n").unwrap();
    fs::write(home_sv.join("dani/nuevo.txt"), "añadido").unwrap();
    let (incr, incr_path) = backup(
        &mut Session::new(false),
        &opts(&origin.mnt, &dest, tmp.path(), &specs, Some(&full_path)),
    )
    .unwrap();
    assert_eq!(incr.verdict(), Verdict::Valid, "{:?}", incr.error);
    assert!(incr
        .subvolumes
        .iter()
        .all(|s| s.parent.is_some() && s.chain.len() == 2));
    assert!(
        incr.commands
            .iter()
            .filter(|c| c.command.starts_with("btrfs send -p"))
            .count()
            >= 2
    );

    // 3. Volver a verificar desde el informe y restaurar en otro Btrfs.
    let items = prior_subvolumes(&incr_path).unwrap();
    let again = verify_subvolumes(&mut Session::new(false), &items, tmp.path(), 1 << 30).unwrap();
    assert_eq!(again.verdict, Verdict::Valid, "{:#?}", again.steps);

    let other = Fs::new(tmp.path(), "destino");
    let restored = restore_many(&mut Session::new(false), &items, &other.mnt).unwrap();
    assert_eq!(restored.len(), 2);
    for (src, label) in [(&root_sv, "@"), (&home_sv, "@home")] {
        let c = compare_trees(src, &other.mnt.join(label)).unwrap();
        assert!(c.identical(), "{label}: {:?}", c.differences);
    }

    // 4. Un informe de un solo subvolumen no sirve de padre para varios.
    let single = tmp.path().join("uno.report.json");
    let text = fs::read_to_string(&full_path)
        .unwrap()
        .replace("\"subvolumes\"", "\"otros\"");
    fs::write(&single, text).unwrap();
    assert!(prior_subvolumes(&single).is_err());

    // 5. Si falta un snapshot de referencia, la verificación queda reducida, no válida.
    let gone = &items[0].artifact.snapshot;
    sh("btrfs", &["subvolume", "delete", gone.to_str().unwrap()]);
    let v = verify_subvolumes(&mut Session::new(false), &items, tmp.path(), 1 << 30).unwrap();
    assert_eq!(v.verdict, Verdict::Reduced);
    let cmp = v.steps.iter().find(|s| s.name == "muestra").unwrap();
    assert_eq!(cmp.status, StepStatus::Skipped);
}
