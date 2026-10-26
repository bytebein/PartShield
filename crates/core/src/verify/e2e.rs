//! Verification on real loop devices. Needs root and btrfs-progs, so it
//! only runs with `PARTSHIELD_SANDBOX=1 PARTSHIELD_E2E=1 cargo test`.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::*;
use crate::cmd::{guard_path, sandboxed};
use crate::send::{send, SendOptions};
use crate::types::Artifact;

/// 4 KiB of this pattern is a data block that appears nowhere else in the
/// scratch image, so the test can find it and damage it.
const MARKER: &[u8; 16] = b"PARTSHIELD-SCRUB";
const BLOCK: usize = 4096;

fn enabled() -> bool {
    if std::env::var_os("PARTSHIELD_E2E").is_none() {
        eprintln!("omitido: define PARTSHIELD_E2E=1 (necesita root y loop devices)");
        return false;
    }
    assert!(
        sandboxed(),
        "las pruebas con loop devices exigen PARTSHIELD_SANDBOX=1"
    );
    true
}

/// A loop-mounted Btrfs with BLOCK_GROUP_TREE, released on drop.
struct Origin {
    loopdev: String,
    mnt: PathBuf,
}

impl Origin {
    fn new(s: &mut Session, dir: &Path) -> Self {
        let img = dir.join("origen.img");
        File::create(&img).unwrap().set_len(1 << 30).unwrap();
        s.run(
            Cmd::new("mkfs.btrfs")
                .arg("-q")
                .arg("-O")
                .arg("block-group-tree")
                .arg(&img),
        )
        .unwrap();
        let loopdev = s
            .run(Cmd::new("losetup").arg("--find").arg("--show").arg(&img))
            .unwrap()
            .trim()
            .to_string();
        assert!(loopdev.starts_with("/dev/loop"), "{loopdev}");
        let mnt = dir.join("mnt");
        fs::create_dir(&mnt).unwrap();
        let me = Origin { loopdev, mnt };
        s.run(Cmd::new("mount").arg(&me.loopdev).arg(&me.mnt))
            .unwrap();
        me
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.mnt).status();
        let _ = Command::new("losetup")
            .arg("--detach")
            .arg(&self.loopdev)
            .status();
    }
}

fn fill(dir: &Path) {
    fs::create_dir_all(dir.join("fotos/2026")).unwrap();
    fs::write(dir.join("notas.txt"), "copias que se restauran de verdad\n").unwrap();
    let noise: Vec<u8> = (0..3_000_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    fs::write(dir.join("fotos/2026/grande.bin"), noise).unwrap();
    fs::write(dir.join("marcador.bin"), MARKER.repeat(64 * 1024)).unwrap();
    fs::write(dir.join("secreto"), "solo para mí").unwrap();
    fs::set_permissions(dir.join("secreto"), fs::Permissions::from_mode(0o600)).unwrap();
    symlink("fotos/2026/grande.bin", dir.join("enlace")).unwrap();
    fs::hard_link(dir.join("notas.txt"), dir.join("fotos/notas-duro.txt")).unwrap();
    for i in 0..40 {
        fs::write(dir.join(format!("fotos/{i:02}.txt")), format!("foto {i}\n")).unwrap();
    }
    xattr::set(&dir.join("notas.txt"), "user.etiqueta", b"importante").unwrap();
}

fn status(v: &Verification, name: &str) -> StepStatus {
    v.steps.iter().find(|s| s.name == name).unwrap().status
}

fn detail<'a>(v: &'a Verification, name: &str) -> &'a str {
    &v.steps.iter().find(|s| s.name == name).unwrap().detail
}

fn statuses(v: &Verification) -> Vec<(&'static str, StepStatus)> {
    v.steps.iter().map(|s| (s.name, s.status)).collect()
}

/// Flips one byte inside the marker block of the scratch image.
fn damage_marker(image: &Path) -> Result<()> {
    guard_path(image)?;
    let mut f = fs::OpenOptions::new().read(true).write(true).open(image)?;
    let want = MARKER.repeat(BLOCK / MARKER.len());
    let mut buf = vec![0u8; 1 << 20];
    let mut base = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            bail!("no se encontró el bloque marcador en {}", image.display());
        }
        // Reads of a regular file fill the buffer except at EOF, and the
        // buffer is a multiple of the block size, so blocks stay aligned.
        if let Some(i) = buf[..n].chunks(BLOCK).position(|b| b == want) {
            let at = base + (i * BLOCK) as u64 + 100;
            f.seek(SeekFrom::Start(at))?;
            f.write_all(&[buf[i * BLOCK + 100] ^ 0xff])?;
            f.sync_all()?;
            return Ok(());
        }
        base += n as u64;
    }
}

struct Case<'a> {
    tmp: &'a Path,
    artifact: &'a Artifact,
}

impl Case<'_> {
    fn verify(&self, reference: Option<&Path>, sample: ContentSample) -> Verification {
        self.verify_hooked(reference, sample, &mut |_| Ok(()))
    }

    fn verify_hooked(
        &self,
        reference: Option<&Path>,
        sample: ContentSample,
        hook: &mut dyn FnMut(&Path) -> Result<()>,
    ) -> Verification {
        run(
            &mut Session::new(false),
            &VerifyOptions {
                streams: &[self.artifact.stream_ref()],
                reference,
                scratch_dir: self.tmp,
                scratch_size: 1 << 30,
            },
            sample,
            hook,
        )
        .unwrap()
    }

    /// A copy of the snapshot that the test can then alter.
    fn altered(&self, name: &str, change: impl FnOnce(&Path)) -> PathBuf {
        let dir = self.artifact.snapshot.parent().unwrap().join(name);
        let ok = Command::new("cp")
            .arg("-a")
            .arg(&self.artifact.snapshot)
            .arg(&dir)
            .status()
            .unwrap()
            .success();
        assert!(ok);
        change(&dir);
        dir
    }
}

#[test]
fn five_steps_on_loop_devices() {
    if !enabled() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let mut s = Session::new(false);
    let origin = Origin::new(&mut s, tmp.path());
    let source = origin.mnt.join("datos");
    s.run(
        Cmd::new("btrfs")
            .arg("subvolume")
            .arg("create")
            .arg(&source),
    )
    .unwrap();
    fill(&source);
    let artifact = send(
        &mut s,
        &SendOptions {
            source: &source,
            dest_dir: &tmp.path().join("copias"),
            snapshot_dir: Some(&origin.mnt),
            name: "prueba",
            zstd_level: 3,
            parent: None,
            hash: HashAlgo::Blake3,
        },
    )
    .unwrap();
    let case = Case {
        tmp: tmp.path(),
        artifact: &artifact,
    };
    let snapshot = artifact.snapshot.as_path();

    // A good copy passes all five steps, with the sample seed recorded.
    let v = case.verify(Some(snapshot), ContentSample::Sample);
    assert_eq!(v.verdict, Verdict::Valid, "{:#?}", v.steps);
    let names: Vec<_> = v.steps.iter().map(|s| s.name).collect();
    assert_eq!(names, STEPS);
    let seed = sample::seed_from(&artifact.digest);
    assert!(
        detail(&v, MUESTRA).contains(&format!("semilla {seed:#018x}")),
        "{}",
        detail(&v, MUESTRA)
    );
    assert!(detail(&v, COMPARACION).contains("scrub sin errores"));
    let c = v.comparison.as_ref().unwrap();
    assert_eq!((c.files, c.total_differences), (45, 0));

    let all = case.verify(Some(snapshot), ContentSample::All);
    assert_eq!(all.verdict, Verdict::Valid, "{:#?}", all.steps);
    assert!(detail(&all, MUESTRA).contains("todos los archivos"));

    // No reference: comparison and sample are skipped, so only reduced.
    let v = case.verify(None, ContentSample::Sample);
    assert_eq!(v.verdict, Verdict::Reduced, "{:#?}", v.steps);
    assert_eq!(
        statuses(&v),
        [
            (RESTAURAR, StepStatus::Passed),
            (ESTRUCTURA, StepStatus::Passed),
            (MONTAJE, StepStatus::Passed),
            (COMPARACION, StepStatus::Skipped),
            (MUESTRA, StepStatus::Skipped),
        ]
    );
    assert!(detail(&v, COMPARACION).contains("scrub sin errores"));

    // No stream hash: the restore step cannot pass, so only reduced.
    let v = run(
        &mut Session::new(false),
        &VerifyOptions {
            streams: &[StreamRef::plain(artifact.stream.clone())],
            reference: Some(snapshot),
            scratch_dir: tmp.path(),
            scratch_size: 1 << 30,
        },
        ContentSample::Sample,
        &mut |_| Ok(()),
    )
    .unwrap();
    assert_eq!(v.verdict, Verdict::Reduced, "{:#?}", v.steps);
    assert_eq!(status(&v, RESTAURAR), StepStatus::Skipped);

    // Reference with the same sizes but other bytes: only the sample sees it.
    let same_size = case.altered("mismo-tamano", |d| {
        fs::write(d.join("fotos/07.txt"), "FOTO 7\n").unwrap();
    });
    let v = case.verify(Some(&same_size), ContentSample::Sample);
    assert_eq!(v.verdict, Verdict::Invalid);
    assert_eq!(status(&v, COMPARACION), StepStatus::Passed);
    assert_eq!(status(&v, MUESTRA), StepStatus::Failed);
    assert!(detail(&v, MUESTRA).contains("contenido distinto en fotos/07.txt"));

    // Metadata changes in the reference fail the comparison step.
    let meta = case.altered("metadatos", |d| {
        fs::set_permissions(d.join("secreto"), fs::Permissions::from_mode(0o644)).unwrap();
        xattr::set(&d.join("notas.txt"), "user.etiqueta", b"otra").unwrap();
        fs::write(d.join("notas.txt"), "otra cosa\n").unwrap();
    });
    let v = case.verify(Some(&meta), ContentSample::Sample);
    assert_eq!(v.verdict, Verdict::Invalid);
    assert_eq!(status(&v, RESTAURAR), StepStatus::Passed);
    assert_eq!(status(&v, COMPARACION), StepStatus::Failed);
    let d = detail(&v, COMPARACION);
    assert!(d.contains("permisos distintos en secreto"), "{d}");
    assert!(d.contains("tamaño distinto en notas.txt"), "{d}");
    assert!(d.contains("scrub sin errores"), "{d}");

    // A data block damaged in the restored image: scrub finds it.
    let mut damaged = false;
    let v = case.verify_hooked(Some(snapshot), ContentSample::Sample, &mut |img| {
        damage_marker(img)?;
        damaged = true;
        Ok(())
    });
    assert!(damaged);
    assert_eq!(v.verdict, Verdict::Invalid, "{:#?}", v.steps);
    assert_eq!(status(&v, ESTRUCTURA), StepStatus::Passed);
    assert_eq!(status(&v, MONTAJE), StepStatus::Passed);
    assert_eq!(status(&v, COMPARACION), StepStatus::Failed);
    let d = detail(&v, COMPARACION);
    assert!(d.contains("csum_errors: 1"), "{d}");
    assert!(d.contains("metadatos de"), "metadata still compared: {d}");
    assert_eq!(status(&v, MUESTRA), StepStatus::Failed);
    assert!(detail(&v, MUESTRA).contains("no se pudo leer marcador.bin en la copia"));

    // A panic halfway through still releases everything.
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        case.verify_hooked(Some(snapshot), ContentSample::Sample, &mut |_| {
            panic!("pánico de prueba")
        })
    }));
    assert!(r.is_err());

    // Nothing left behind: no loop device or image of ours (other
    // processes may be verifying at the same time, so only ours count).
    let loops = s
        .run(
            Cmd::new("losetup")
                .arg("--list")
                .arg("--noheadings")
                .arg("--output")
                .arg("BACK-FILE"),
        )
        .unwrap();
    let ours = tmp.path().to_string_lossy().into_owned();
    assert!(
        !loops
            .lines()
            .any(|l| l.contains(&ours) && l.contains("partshield-verify")),
        "{loops}"
    );
    let leftovers: Vec<_> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("partshield-verify-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}
