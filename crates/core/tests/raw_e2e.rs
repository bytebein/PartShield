//! Modo raw de punta a punta sobre un Btrfs real con BLOCK_GROUP_TREE.
//!
//! Necesita root y loop devices: `PARTSHIELD_SANDBOX=1 PARTSHIELD_E2E=1 cargo test --test raw_e2e`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use partshield_core::cmd::Session;
use partshield_core::raw::{self, load_from_report};
use partshield_core::report::sign;
use partshield_core::types::{HashAlgo, StepStatus, Verdict, Verification};
use partshield_core::verify::compare::compare_trees;
use partshield_core::{backup_raw, RawOptions};

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

/// Archivo + loop, con desmontaje y liberación garantizados.
struct Loop {
    dev: String,
    mnt: PathBuf,
}

impl Loop {
    fn new(dir: &Path, name: &str, size: u64) -> Self {
        let img = dir.join(format!("{name}.img"));
        fs::File::create(&img).unwrap().set_len(size).unwrap();
        let dev = sh("losetup", &["--find", "--show", img.to_str().unwrap()]);
        let mnt = dir.join(format!("{name}-mnt"));
        fs::create_dir(&mnt).unwrap();
        Loop { dev, mnt }
    }

    fn mount(&self, opts: &str) {
        sh(
            "mount",
            &["-o", opts, &self.dev, self.mnt.to_str().unwrap()],
        );
    }

    fn umount(&self) {
        sh("umount", &[self.mnt.to_str().unwrap()]);
    }
}

impl Drop for Loop {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.mnt).status();
        let _ = Command::new("losetup")
            .arg("--detach")
            .arg(&self.dev)
            .status();
    }
}

fn step(v: &Verification, name: &str) -> StepStatus {
    v.steps.iter().find(|s| s.name == name).unwrap().status
}

#[test]
fn raw_image_backup_verify_restore() {
    if std::env::var_os("PARTSHIELD_E2E").is_none() {
        eprintln!("omitido: define PARTSHIELD_E2E=1 (necesita root y loop devices)");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let origin = Loop::new(tmp.path(), "origen", 512 << 20);
    sh(
        "mkfs.btrfs",
        &["-q", "-O", "block-group-tree", "-L", "origen", &origin.dev],
    );
    origin.mount("compress=zstd");
    fs::create_dir(origin.mnt.join("fotos")).unwrap();
    let noise: Vec<u8> = (0..3_000_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    fs::write(origin.mnt.join("fotos/grande.bin"), &noise).unwrap();
    fs::write(origin.mnt.join("notas.txt"), "imagen sector a sector\n").unwrap();
    sh("sync", &[]);

    let dest = tmp.path().join("copias");
    let key = tmp.path().join("clave");
    let opts = RawOptions {
        device: Path::new(&origin.dev),
        dest_dir: &dest,
        scratch_dir: Some(tmp.path()),
        zstd_level: 3,
        hash: HashAlgo::Blake3,
        sign_key: Some(&key),
    };

    // 1. Montado en lectura-escritura: se niega y no deja stream.
    let (refused, _) = backup_raw(&mut Session::new(false), &opts).unwrap();
    assert_eq!(refused.verdict(), Verdict::Invalid);
    assert!(
        refused
            .error
            .as_deref()
            .unwrap()
            .contains("lectura-escritura"),
        "{:?}",
        refused.error
    );
    assert!(refused.artifact.is_none());

    // 2. En solo lectura: copia válida con los cinco pasos.
    sh("mount", &["-o", "remount,ro", origin.mnt.to_str().unwrap()]);
    let (report, report_path) = backup_raw(&mut Session::new(false), &opts).unwrap();
    let v = report.verification.as_ref().unwrap();
    assert_eq!(
        report.verdict(),
        Verdict::Valid,
        "{:?} {:#?}",
        report.error,
        v.steps
    );
    let names: Vec<_> = v.steps.iter().map(|s| s.name).collect();
    assert_eq!(
        names,
        [
            "restaurar",
            "estructura",
            "montaje",
            "comparacion",
            "muestra"
        ]
    );
    assert!(
        report.superblock.is_some(),
        "debe registrar el Btrfs detectado"
    );
    // Informe firmado y en HTML junto al JSON.
    assert!(report.signature.is_some());
    let pk = sign::load_public_key(&key.with_extension("pub")).unwrap();
    let json = fs::read_to_string(&report_path).unwrap();
    sign::verify_signature(&json, &pk).unwrap();
    assert!(json.contains("\"size_bytes\": 536870912"));
    assert!(sign::verify_signature(&json.replace("\"raw\"", "\"raw\" "), &pk).is_ok());
    assert!(json.contains("\"size_bytes\": 536870912"));
    assert!(sign::verify_signature(
        &json.replacen("\"size_bytes\": 536870912", "\"size_bytes\": 536870913", 1),
        &pk
    )
    .is_err());
    let html = fs::read_to_string(report_path.with_extension("html")).unwrap();
    assert!(html.contains("VÁLIDA"));
    let image = report.raw.clone().unwrap();
    assert_eq!(image.size_bytes, 512 << 20);
    let artifact = report.artifact.as_ref().unwrap();
    assert!(
        artifact.compressed_bytes < image.size_bytes / 20,
        "el espacio vacío debe comprimirse"
    );

    // 3. Restaurar en otro loop del mismo tamaño y montarlo: mismos archivos.
    let (stream, loaded) = load_from_report(&report_path).unwrap().unwrap();
    assert_eq!(loaded, image);
    let copy = Loop::new(tmp.path(), "copia", 512 << 20);
    raw::restore_to(
        &mut Session::new(false),
        &stream,
        &image,
        Path::new(&copy.dev),
    )
    .unwrap();
    copy.mount("ro");
    let c = compare_trees(&origin.mnt, &copy.mnt).unwrap();
    assert!(c.identical(), "{:?}", c.differences);
    copy.umount();

    // 4. Un destino más pequeño se rechaza sin escribir.
    let small = Loop::new(tmp.path(), "pequeno", 256 << 20);
    let err = raw::restore_to(
        &mut Session::new(false),
        &stream,
        &image,
        Path::new(&small.dev),
    )
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("al menos igual de grande"),
        "{err:#}"
    );

    // 5. El origen cambia después de la copia: la muestra lo detecta.
    origin.umount();
    origin.mount("rw");
    fs::write(origin.mnt.join("notas.txt"), "cambiado después\n").unwrap();
    sh(
        "btrfs",
        &["filesystem", "sync", origin.mnt.to_str().unwrap()],
    );
    origin.umount();
    // Escribir más datos para que el cambio toque bloques muestreados no es
    // determinista; se fuerza tocando el principio, que siempre se muestrea.
    let mut dev = fs::OpenOptions::new()
        .write(true)
        .open(&origin.dev)
        .unwrap();
    std::io::Write::write_all(&mut dev, &[0xAB; 512]).unwrap();
    drop(dev);
    let v = raw::verify(&mut Session::new(false), &stream, &image, tmp.path()).unwrap();
    assert_eq!(v.verdict, Verdict::Invalid);
    assert_eq!(step(&v, "muestra"), StepStatus::Failed);
    assert_eq!(step(&v, "comparacion"), StepStatus::Passed);

    let loops = sh(
        "losetup",
        &["--list", "--noheadings", "--output", "BACK-FILE"],
    );
    assert!(!loops.contains("partshield-raw-verify"), "{loops}");
}

/// Los sistemas de archivos de un disco entero (EFI, Windows, Linux…) pasan
/// el paso «estructura» con su propio fsck de solo lectura, y la copia sale
/// válida, no «reducida».
#[test]
fn raw_image_checks_structure_of_other_filesystems() {
    if std::env::var_os("PARTSHIELD_E2E").is_none() {
        eprintln!("omitido: define PARTSHIELD_E2E=1 (necesita root y loop devices)");
        return;
    }
    let have = |p: &str| {
        Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {p}"))
            .output()
            .is_ok_and(|o| o.status.success())
    };
    let cases: [(&str, &[&str], &str); 5] = [
        ("mkfs.ext4", &["-q"], "e2fsck"),
        ("mkfs.vfat", &[], "fsck.vfat"),
        ("mkfs.exfat", &[], "fsck.exfat"),
        ("mkfs.xfs", &["-q"], "xfs_repair"),
        ("mkfs.ntfs", &["-Q", "-q", "-F"], "ntfsfix"),
    ];
    for (mkfs, args, checker) in cases {
        if !have(mkfs) || !have(checker) {
            eprintln!("omitido {mkfs}: falta {mkfs} o {checker}");
            continue;
        }
        let tmp = tempfile::tempdir().unwrap();
        let origin = Loop::new(tmp.path(), "origen", 320 << 20);
        let mut a = args.to_vec();
        a.push(&origin.dev);
        sh(mkfs, &a);
        let mounted = Command::new("mount")
            .arg(&origin.dev)
            .arg(&origin.mnt)
            .status()
            .is_ok_and(|st| st.success());
        if !mounted {
            eprintln!("omitido {mkfs}: este kernel no lo monta");
            continue;
        }
        fs::write(origin.mnt.join("nota.txt"), "hola\n").unwrap();
        sh("sync", &[]);
        origin.umount();

        let dest = tmp.path().join("copias");
        let (report, _) = backup_raw(
            &mut Session::new(false),
            &RawOptions {
                device: Path::new(&origin.dev),
                dest_dir: &dest,
                scratch_dir: Some(tmp.path()),
                zstd_level: 3,
                hash: HashAlgo::Blake3,
                sign_key: None,
            },
        )
        .unwrap();
        let v = report.verification.as_ref().unwrap();
        assert_eq!(
            step(v, "estructura"),
            StepStatus::Passed,
            "{mkfs}: {:#?}",
            v.steps
        );
        assert_eq!(report.verdict(), Verdict::Valid, "{mkfs}: {:#?}", v.steps);
    }
}
