//! End-to-end test on a real Btrfs with BLOCK_GROUP_TREE.
//!
//! Needs root, loop devices and btrfs-progs, so it only runs with
//! `PARTSHIELD_E2E=1 cargo test --test e2e`.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

mod common;
use common::{sh, FsBuilder, TestFs};

use partshield_core::cmd::Session;
use partshield_core::report::load_prior;
use partshield_core::send::restore::{restore, RestoreOptions};
use partshield_core::types::{
    CompatRo, HashAlgo, Mode, StepStatus, StreamRef, Verdict, Verification,
};
use partshield_core::verify::compare::compare_trees;
use partshield_core::verify::{verify, VerifyOptions};
use partshield_core::{backup, BackupOptions};

/// A 1 GiB Btrfs with BLOCK_GROUP_TREE mounted with compress=zstd
/// (`common::TestFs`: unmounted and detached on drop, even on panic).
fn new_fs(dir: &Path) -> TestFs {
    FsBuilder::new().size(1 << 30).label("origen").build_in(dir)
}

fn fill(dir: &Path) {
    fs::create_dir_all(dir.join("fotos/2026")).unwrap();
    fs::write(dir.join("notas.txt"), "copias que se restauran de verdad\n").unwrap();
    let noise: Vec<u8> = (0..5_000_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    fs::write(dir.join("fotos/2026/grande.bin"), noise).unwrap();
    fs::write(dir.join("secreto"), "solo para mí").unwrap();
    fs::set_permissions(dir.join("secreto"), fs::Permissions::from_mode(0o600)).unwrap();
    symlink("fotos/2026/grande.bin", dir.join("enlace")).unwrap();
}

fn step(v: &Verification, name: &str) -> StepStatus {
    v.steps.iter().find(|s| s.name == name).unwrap().status
}

#[test]
fn backup_verify_and_detect_corruption() {
    if !common::e2e_enabled("backup_verify_and_detect_corruption") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let origin = new_fs(tmp.path());
    let source = origin.top.join("datos");
    sh("btrfs", &["subvolume", "create", source.to_str().unwrap()]);
    fill(&source);
    let dest = tmp.path().join("copias");

    // 1. A good backup is restored, compared and reported as valid.
    let mut s = Session::new(false);
    let (report, report_path) = backup(
        &mut s,
        &BackupOptions {
            source: &source,
            dest_dir: &dest,
            snapshot_dir: Some(&origin.top),
            scratch_dir: Some(tmp.path()),
            keep_snapshot: true,
            zstd_level: 3,
            parent_report: None,
            hash: HashAlgo::Blake3,
            sign_key: None,
            subvolumes: &[],
            capture_layout: false,
            disk: None,
        },
    )
    .unwrap();
    assert_eq!(report.error, None);
    let v = report.verification.as_ref().unwrap();
    assert_eq!(report.verdict(), Verdict::Valid, "{:#?}", v.steps);
    assert_eq!(v.comparison.as_ref().unwrap().files, 3);
    assert!(report_path.exists());

    let sb = report.superblock.as_ref().unwrap();
    assert!(sb.features.compat_ro.contains(CompatRo::BLOCK_GROUP_TREE));
    let partclone = report
        .modes
        .iter()
        .find(|m| m.mode == Mode::Partclone)
        .unwrap();
    assert!(
        !partclone.allowed,
        "partclone sin versión probada no debe permitirse"
    );
    assert!(report
        .commands
        .iter()
        .any(|c| c.command.starts_with("btrfs send")));

    let artifact = report.artifact.as_ref().unwrap();
    let opts = |stream: &Path, reference: &Path| -> Verification {
        verify(
            &mut Session::new(false),
            &VerifyOptions {
                streams: &[StreamRef {
                    path: stream.to_path_buf(),
                    digest: Some(artifact.digest.clone()),
                    encryption: None,
                    chunks: None,
                }],
                reference: Some(reference),
                scratch_dir: tmp.path(),
                scratch_size: 1 << 30,
            },
        )
        .unwrap()
    };

    // 2. Without a reference the verdict is reduced, never valid.
    let reduced = verify(
        &mut Session::new(false),
        &VerifyOptions {
            streams: &[StreamRef::plain(artifact.stream.clone())],
            reference: None,
            scratch_dir: tmp.path(),
            scratch_size: 1 << 30,
        },
    )
    .unwrap();
    assert_eq!(reduced.verdict, Verdict::Reduced);

    // 3. Source changed after the backup: content step fails.
    let changed = tmp.path().join("cambiado");
    sh(
        "cp",
        &[
            "-a",
            artifact.snapshot.to_str().unwrap(),
            changed.to_str().unwrap(),
        ],
    );
    fs::write(changed.join("notas.txt"), "otra cosa\n").unwrap();
    let v = opts(&artifact.stream, &changed);
    assert_eq!(v.verdict, Verdict::Invalid);
    assert_eq!(step(&v, "comparacion"), StepStatus::Failed);
    assert_eq!(step(&v, "restaurar"), StepStatus::Passed);

    // 4. A flipped byte in the stream file is caught.
    let flipped = tmp.path().join("volteado.btrfs.zst");
    fs::copy(&artifact.stream, &flipped).unwrap();
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&flipped)
        .unwrap();
    let mid = f.metadata().unwrap().len() / 2;
    let mut b = [0u8; 1];
    f.seek(SeekFrom::Start(mid)).unwrap();
    std::io::Read::read_exact(&mut f, &mut b).unwrap();
    f.seek(SeekFrom::Start(mid)).unwrap();
    f.write_all(&[b[0] ^ 0xff]).unwrap();
    drop(f);
    let v = opts(&flipped, &artifact.snapshot);
    assert_eq!(v.verdict, Verdict::Invalid);
    assert_eq!(step(&v, "restaurar"), StepStatus::Failed);

    // 5. A truncated stream (like a copy cut short) cannot be restored.
    let cut = tmp.path().join("cortado.btrfs.zst");
    let bytes = fs::read(&artifact.stream).unwrap();
    fs::write(&cut, &bytes[..bytes.len() / 3]).unwrap();
    let v = opts(&cut, &artifact.snapshot);
    assert_eq!(v.verdict, Verdict::Invalid);
    assert_eq!(step(&v, "restaurar"), StepStatus::Failed);

    // 6. Incremental backup on top of the first: only the changes travel,
    //    and verification restores the whole chain.
    fs::write(source.join("notas.txt"), "segunda versión\n").unwrap();
    fs::write(source.join("nuevo.txt"), "añadido después").unwrap();
    fs::remove_file(source.join("secreto")).unwrap();
    let (incr, incr_path) = backup(
        &mut Session::new(false),
        &BackupOptions {
            source: &source,
            dest_dir: &dest,
            snapshot_dir: Some(&origin.top),
            scratch_dir: Some(tmp.path()),
            keep_snapshot: true,
            zstd_level: 3,
            parent_report: Some(&report_path),
            hash: HashAlgo::Blake3,
            sign_key: None,
            subvolumes: &[],
            capture_layout: false,
            disk: None,
        },
    )
    .unwrap();
    let iv = incr.verification.as_ref().unwrap();
    assert_eq!(
        incr.verdict(),
        Verdict::Valid,
        "{:?} {:#?}",
        incr.error,
        iv.steps
    );
    assert_eq!(incr.chain.len(), 2);
    assert!(incr
        .commands
        .iter()
        .any(|c| c.command.starts_with("btrfs send -p")));
    let incr_artifact = incr.artifact.as_ref().unwrap();
    assert!(incr_artifact.compressed_bytes * 10 < artifact.compressed_bytes);

    // 7. Restoring the chain onto another Btrfs gives back the current source.
    let other_dir = tmp.path().join("destino");
    fs::create_dir(&other_dir).unwrap();
    let mut other = new_fs(&other_dir);
    let prior = load_prior(&incr_path).unwrap();
    assert!(prior.valid);
    let restored = restore(
        &mut Session::new(false),
        &RestoreOptions {
            streams: &prior.chain,
            target: &other.top,
            writable_name: Some("datos"),
        },
    )
    .unwrap();
    let writable = restored.writable.unwrap();
    let c = compare_trees(&source, &writable).unwrap();
    assert!(c.identical(), "{:?}", c.differences);
    fs::write(writable.join("escribible.txt"), "sí").unwrap();

    // 8. A damaged stream is refused before anything is received.
    let empty = other.top.join("vacio");
    sh("btrfs", &["subvolume", "create", empty.to_str().unwrap()]);
    let err = restore(
        &mut Session::new(false),
        &RestoreOptions {
            streams: &[StreamRef {
                path: flipped.clone(),
                digest: Some(artifact.digest.clone()),
                encryption: None,
                chunks: None,
            }],
            target: &empty,
            writable_name: None,
        },
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("dañado"), "{err:#}");
    assert_eq!(fs::read_dir(&empty).unwrap().count(), 0);

    // Phase 0 gate: the restored filesystem passes btrfs check and the
    // restored subvolume mounts on its own and matches the source.
    other.unmount_all();
    let check = other.check();
    assert!(
        check.status.success(),
        "btrfs check: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    let mounted = tmp.path().join("copia-montada");
    other.mount_subvol("datos", &mounted, ",ro");
    let c = compare_trees(&source, &mounted).unwrap();
    assert_eq!(c.total_differences, 1, "{:?}", c.differences);
    assert!(
        c.differences[0].contains("escribible.txt"),
        "{:?}",
        c.differences
    );
    common::assert_same_tree(&source, &mounted, &["escribible.txt"]);

    // 9. No incremental on top of a backup that did not verify.
    let bad_report = tmp.path().join("mala.report.json");
    let text = fs::read_to_string(&report_path)
        .unwrap()
        .replace("\"verdict\": \"valid\"", "\"verdict\": \"invalid\"");
    fs::write(&bad_report, text).unwrap();
    let (refused, _) = backup(
        &mut Session::new(false),
        &BackupOptions {
            source: &source,
            dest_dir: &dest,
            snapshot_dir: Some(&origin.top),
            scratch_dir: Some(tmp.path()),
            keep_snapshot: false,
            zstd_level: 3,
            parent_report: Some(&bad_report),
            hash: HashAlgo::Blake3,
            sign_key: None,
            subvolumes: &[],
            capture_layout: false,
            disk: None,
        },
    )
    .unwrap();
    assert_eq!(refused.verdict(), Verdict::Invalid);
    assert!(refused.error.unwrap().contains("no es válida"));

    // No loop devices or mounts left behind by verification.
    let loops = sh(
        "losetup",
        &["--list", "--noheadings", "--output", "BACK-FILE"],
    );
    assert!(!loops.contains("partshield-verify"), "{loops}");
}
