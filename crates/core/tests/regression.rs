//! Arnés de regresión: un test de punta a punta por tipo de contenido.
//!
//! Cada caso hace la puerta de la Fase 0 completa sobre un Btrfs con
//! BLOCK_GROUP_TREE montado con compress=zstd: `backup` (que ya restaura y
//! verifica), `report::load_prior`, `send::restore::restore` sobre otro
//! Btrfs, `btrfs check`, montar la copia restaurada por sí sola
//! (`subvol=`) y compararla con el origen (contenido, tipo, permisos,
//! dueños, symlinks, nlink, mtime, xattrs y hardlinks).
//!
//! Solo corren con `PARTSHIELD_SANDBOX=1 PARTSHIELD_E2E=1` y como root.

mod common;

use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use common::harness::{self, assert_backup_valid, backup_opts, round_trip, Options};
use common::{content, e2e_enabled, sh, FsBuilder};
use partshield_core::backup;
use partshield_core::cmd::Session;
use partshield_core::report::load_prior;
use partshield_core::send::restore::{restore, RestoreOptions};
use partshield_core::types::{StepStatus, StreamRef, Verdict};
use partshield_core::verify::{verify, VerifyOptions};

macro_rules! skip_unless_e2e {
    () => {
        if !e2e_enabled(module_path!()) {
            return;
        }
    };
}

#[test]
fn caso_grandes_incompresibles() {
    skip_unless_e2e!();
    let rt = round_trip("incompresibles", Options::default(), |d, _| {
        content::big_incompressible(d)
    });
    let c = rt.report.verification.unwrap().comparison.unwrap();
    assert!(c.bytes >= 55 << 20, "{c:?}");
}

#[test]
fn caso_muy_compresibles() {
    skip_unless_e2e!();
    let rt = round_trip("compresibles", Options::default(), |d, _| {
        content::highly_compressible(d, 200)
    });
    // compress=zstd de verdad: el origen ocupa en disco mucho menos.
    match common::compsize(&rt.source) {
        Some((uncompressed, on_disk)) => {
            eprintln!("compsize origen: {uncompressed} B sin comprimir, {on_disk} B en disco");
            assert!(uncompressed >= 200 << 20);
            assert!(
                on_disk * 10 < uncompressed,
                "el origen no está comprimido: {on_disk} de {uncompressed}"
            );
        }
        None => {
            panic!("falta compsize (paquete btrfs-compsize): no se puede comprobar la compresión")
        }
    }
    // El destino también se monta con compress=zstd.
    let (u, d) = common::compsize(&rt.mounted_copy).unwrap();
    eprintln!("compsize restaurado: {u} B sin comprimir, {d} B en disco");
    assert!(d * 10 < u, "la copia restaurada no se recomprimió");
    // Y el stream comprimido es pequeño.
    let a = rt.report.artifact.as_ref().unwrap();
    assert!(a.compressed_bytes * 20 < a.stream_bytes, "{a:?}");
}

#[test]
fn caso_dispersos() {
    skip_unless_e2e!();
    let rt = round_trip("dispersos", Options::default(), |d, _| {
        content::sparse(d, 256 << 20)
    });
    use std::os::unix::fs::MetadataExt;
    // Los huecos siguen siendo huecos en la copia restaurada.
    for name in ["islas.img", "cola-hueca.img", "solo-hueco.img"] {
        let src = &rt.tree.entries[&Path::new("dispersos").join(name)];
        let md = rt
            .mounted_copy
            .join("dispersos")
            .join(name)
            .symlink_metadata()
            .unwrap();
        eprintln!(
            "{name}: aparente {} B, origen ocupa {} B, copia ocupa {} B",
            md.len(),
            src.allocated,
            md.blocks() * 512
        );
        assert!(
            md.blocks() * 512 <= src.allocated + (1 << 20),
            "{name} perdió los huecos: {} B en la copia, {} B en el origen",
            md.blocks() * 512,
            src.allocated
        );
    }
}

#[test]
fn caso_hardlinks() {
    skip_unless_e2e!();
    let rt = round_trip("hardlinks", Options::default(), |d, _| {
        content::hardlinks(d)
    });
    assert_eq!(rt.tree.link_groups.len(), 2, "{:?}", rt.tree.link_groups);
}

#[test]
fn caso_symlinks() {
    skip_unless_e2e!();
    let rt = round_trip("symlinks", Options::default(), |d, _| content::symlinks(d));
    let target = fs::read_link(rt.mounted_copy.join("simbolicos/largo")).unwrap();
    assert_eq!(target.as_os_str().len(), 2003);
}

#[test]
fn caso_nombres_raros() {
    skip_unless_e2e!();
    let rt = round_trip("nombres", Options::default(), |d, _| content::odd_names(d));
    assert!(rt
        .mounted_copy
        .join("nombres raros/ñandú-Ærø-日本語-😀.txt")
        .exists());
}

#[test]
fn caso_xattrs() {
    skip_unless_e2e!();
    let rt = round_trip("xattrs", Options::default(), |d, _| content::xattrs(d));
    let x = &rt.tree.entries[Path::new("xattrs/con-xattr")].xattrs;
    assert!(x.contains_key("user.comentario"), "{x:?}");
    assert!(x.contains_key("trusted.partshield"), "{x:?}");
    if common::have("setcap") {
        let c = &rt.tree.entries[Path::new("xattrs/capacidad")].xattrs;
        assert!(c.contains_key("security.capability"), "{c:?}");
    }
}

#[test]
fn caso_permisos_y_propietarios() {
    skip_unless_e2e!();
    let rt = round_trip("permisos", Options::default(), |d, _| {
        content::perms_owners(d)
    });
    let e = &rt.tree.entries[Path::new("permisos/setuid")];
    assert_eq!(e.mode, 0o4755);
    let e = &rt.tree.entries[Path::new("permisos/raro")];
    assert_eq!((e.uid, e.gid), (123_456, 654_321));
}

#[test]
fn caso_vacios() {
    skip_unless_e2e!();
    let rt = round_trip("vacios", Options::default(), |d, _| content::empty_files(d));
    let c = rt.report.verification.unwrap().comparison.unwrap();
    assert_eq!(c.bytes, 0);
    assert_eq!(c.files, 20);
}

#[test]
fn caso_muchos_pequenos() {
    skip_unless_e2e!();
    let rt = round_trip("pequenos", Options::default(), |d, _| {
        content::many_small(d, 20_000)
    });
    assert_eq!(
        rt.report.verification.unwrap().comparison.unwrap().files,
        20_000
    );
}

/// `@` y `@home` montados como en un sistema real (`subvol=@` en /,
/// `subvol=@home` en /home); cada subvolumen se copia desde su punto de
/// montaje (el dispositivo sale como `/dev/loopN[/@home]` en findmnt) y se
/// restauran los dos en su sitio.
#[test]
fn caso_subvolumenes_montados() {
    skip_unless_e2e!();
    subvolumes("montados", false);
}

/// Lo mismo con `@home/.snapshots` (snapper) anidado dentro de `@home` y un
/// snapshot dentro de `.snapshots`.
#[test]
fn caso_subvolumenes_anidados() {
    skip_unless_e2e!();
    subvolumes("anidados", true);
}

fn subvolumes(name: &str, nested: bool) {
    let tmp = harness::tempdir(name);
    let mut b = FsBuilder::new().subvolume("@").subvolume("@home");
    if nested {
        b = b.subvolume("@home/.snapshots");
    }
    let mut src = b.build_in(tmp.path());
    content::everything(&src.top.join("@"));
    fs::create_dir_all(src.top.join("@/home")).unwrap();
    content::odd_names(&src.top.join("@home"));
    content::hardlinks(&src.top.join("@home"));
    if nested {
        fs::write(src.top.join("@home/.snapshots/info.xml"), "<snapper/>").unwrap();
        fs::create_dir(src.top.join("@home/.snapshots/1")).unwrap();
        sh(
            "btrfs",
            &[
                OsStr::new("subvolume"),
                OsStr::new("snapshot"),
                OsStr::new("-r"),
                src.top.join("@home").as_os_str(),
                src.top.join("@home/.snapshots/1/snapshot").as_os_str(),
            ],
        );
    }
    let sys = tmp.path().join("sistema");
    src.mount_subvol("@", &sys, "");
    src.mount_subvol("@home", &sys.join("home"), "");
    src.sync();

    let dest = tmp.path().join("copias");
    let scratch = tmp.path().join("scratch");
    let snaps = src.top.clone();
    let mut sources = vec![("@", sys.clone()), ("@home", sys.join("home"))];
    if nested {
        sources.push(("@home/.snapshots", sys.join("home/.snapshots")));
    }
    let mut chains = Vec::new();
    for (name, path) in &sources {
        let (report, path_r) = backup(
            &mut Session::new(false),
            &backup_opts(path, &snaps, &dest, &scratch, None),
        )
        .unwrap();
        assert_backup_valid(&report);
        // El hueco de .snapshots no invalida la copia de @home, pero se avisa.
        if nested && *name == "@home" {
            assert!(
                report.warnings.iter().any(|w| w.contains(".snapshots")),
                "{:?}",
                report.warnings
            );
        }
        let dev = report
            .device
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(dev.starts_with("/dev/loop") && !dev.contains('['), "{dev}");
        chains.push((name.to_string(), load_prior(&path_r).unwrap().chain));
    }

    let mut dst = FsBuilder::new().label("destino").build_in(tmp.path());
    for (name, chain) in &chains {
        let r = restore(
            &mut Session::new(false),
            &RestoreOptions {
                streams: chain,
                target: &dst.top,
                writable_name: None,
            },
        )
        .unwrap();
        // Cada subvolumen restaurado, en su sitio.
        let place = dst.top.join(name);
        if place.exists() {
            fs::remove_dir(&place).unwrap();
        }
        sh(
            "btrfs",
            &[
                OsStr::new("subvolume"),
                OsStr::new("snapshot"),
                r.received.as_os_str(),
                place.as_os_str(),
            ],
        );
    }
    dst.unmount_all();
    assert!(dst.check().status.success());
    let restored_sys = tmp.path().join("restaurado");
    dst.mount_subvol("@", &restored_sys, ",ro");
    dst.mount_subvol("@home", &restored_sys.join("home"), ",ro");

    common::assert_same_tree(&sys, &restored_sys, &["home"]);
    // El snapshot de snapper (.snapshots/1/snapshot) es otro subvolumen
    // anidado que no se ha copiado; el resto debe ser idéntico.
    common::assert_same_tree(
        &sys.join("home"),
        &restored_sys.join("home"),
        &[".snapshots/1/snapshot"],
    );
}

/// Todo junto, una incremental encima y `verify::verify` llamado aparte.
#[test]
fn caso_todo_junto_con_incremental() {
    skip_unless_e2e!();
    let rt = round_trip("todo", Options::default(), |d, _| content::everything(d));

    // Cambios de todos los tipos y una incremental.
    let s = &rt.source;
    fs::write(s.join("compresible/registro.log"), "corto ahora").unwrap();
    fs::remove_dir_all(s.join("pequeños/d007")).unwrap();
    fs::rename(s.join("enlaces/duro1"), s.join("enlaces/duro1-movido")).unwrap();
    content::many_small(&s.join("nuevos"), 300);
    sh(
        "setfattr",
        &[
            OsStr::new("-x"),
            OsStr::new("user.comentario"),
            s.join("xattrs/con-xattr").as_os_str(),
        ],
    );
    rt.source_fs.sync();
    let scratch = rt.tmp.path().join("scratch");
    let (incr, incr_path) = backup(
        &mut Session::new(false),
        &backup_opts(
            s,
            &rt.source_fs.top,
            &rt.tmp.path().join("copias"),
            &scratch,
            Some(&rt.report_path),
        ),
    )
    .unwrap();
    assert_backup_valid(&incr);
    assert_eq!(incr.chain.len(), 2);

    // verify::verify por su cuenta sobre la cadena, contra el snapshot.
    let snap = incr.artifact.as_ref().unwrap().snapshot.clone();
    let v = verify(
        &mut Session::new(false),
        &VerifyOptions {
            streams: &incr.chain,
            reference: Some(&snap),
            scratch_dir: &scratch,
            scratch_size: 2 << 30,
        },
    )
    .unwrap();
    assert_eq!(v.verdict, Verdict::Valid, "{:#?}", v.steps);
    assert!(v.steps.iter().all(|s| s.status == StepStatus::Passed));

    // La cadena entera sobre un Btrfs nuevo, montada y comparada.
    let prior = load_prior(&incr_path).unwrap();
    assert!(prior.valid);
    let mut dst = FsBuilder::new().label("destino2").build_in(rt.tmp.path());
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
    assert!(dst.check().status.success());
    let m = rt.tmp.path().join("cadena-montada");
    dst.mount_subvol("datos", &m, ",ro");
    common::assert_same_tree(s, &m, &[]);
}

/// Un disperso de 3 GiB aparentes con poco dato, mayor que la imagen
/// temporal de 1 GiB: los huecos no se materializan al restaurar.
#[test]
fn caso_disperso_grande() {
    skip_unless_e2e!();
    round_trip(
        "disperso-grande",
        Options {
            source_size: 4 << 30,
            target_size: 8 << 30,
            exclude: vec![],
        },
        |d, _| content::sparse(d, 3 << 30),
    );
}

// ------------------------------------------------------------------- bugs
//
// Casos que hoy fallan por un fallo en otro módulo (no en el test). Se
// ejecutan con `cargo test --test regression -- --ignored`; el motivo está
// en el atributo. Cuando el módulo se arregle, quita el #[ignore].

/// Un archivo muy compresible más grande que la imagen temporal de
/// verificación: el origen (compress=zstd) ocupa poco, `scratch_size` se
/// calcula con `bytes_used` (lib.rs) y la imagen temporal se monta sin
/// compresión (verify), así que `btrfs receive` se queda sin espacio.
#[test]

fn bug_compresible_grande_desborda_scratch() {
    skip_unless_e2e!();
    round_trip(
        "compresible-grande",
        Options {
            source_size: 4 << 30,
            target_size: 4 << 30,
            exclude: vec![],
        },
        |d, _| content::highly_compressible(d, 1536),
    );
}

fn verify_against(reference: &Path, chain: &[StreamRef], scratch: &Path) -> Verdict {
    verify(
        &mut Session::new(false),
        &VerifyOptions {
            streams: chain,
            reference: Some(reference),
            scratch_dir: scratch,
            scratch_size: 2 << 30,
        },
    )
    .unwrap()
    .verdict
}

/// `verify` no compara xattrs: una referencia sin el xattr pasa igual.
#[test]

fn bug_verify_no_compara_xattrs() {
    skip_unless_e2e!();
    let rt = round_trip("verify-xattrs", Options::default(), |d, _| {
        content::xattrs(d)
    });
    let changed = rt.tmp.path().join("referencia");
    let snap = &rt.report.artifact.as_ref().unwrap().snapshot;
    sh(
        "cp",
        &[OsStr::new("-a"), snap.as_os_str(), changed.as_os_str()],
    );
    sh(
        "setfattr",
        &[
            OsStr::new("-x"),
            OsStr::new("user.comentario"),
            changed.join("xattrs/con-xattr").as_os_str(),
        ],
    );
    let v = verify_against(&changed, &rt.prior.chain, &rt.tmp.path().join("s2"));
    assert_eq!(v, Verdict::Invalid, "un xattr perdido no se detecta");
}

/// `verify` no compara hardlinks: dos copias independientes pasan igual.
#[test]

fn bug_verify_no_compara_hardlinks() {
    skip_unless_e2e!();
    let rt = round_trip("verify-hardlinks", Options::default(), |d, _| {
        content::hardlinks(d)
    });
    let changed = rt.tmp.path().join("referencia");
    let snap = &rt.report.artifact.as_ref().unwrap().snapshot;
    sh(
        "cp",
        &[OsStr::new("-a"), snap.as_os_str(), changed.as_os_str()],
    );
    let dup = changed.join("enlaces/duro1");
    let data = fs::read(&dup).unwrap();
    fs::remove_file(&dup).unwrap();
    fs::write(&dup, data).unwrap();
    let v = verify_against(&changed, &rt.prior.chain, &rt.tmp.path().join("s2"));
    assert_eq!(v, Verdict::Invalid, "un hardlink roto no se detecta");
}

/// Dos verificaciones a la vez en el mismo proceso y el mismo directorio
/// temporal: la imagen se llama `partshield-verify-<pid>.img`, así que
/// las dos usan el mismo archivo.
#[test]

fn bug_verify_en_paralelo_mismo_scratch() {
    skip_unless_e2e!();
    let rt = round_trip("verify-paralelo", Options::default(), |d, _| {
        content::many_small(d, 2000)
    });
    let scratch = rt.tmp.path().join("compartido");
    let snap = rt.report.artifact.as_ref().unwrap().snapshot.clone();
    let verdicts: Vec<Verdict> = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..2)
            .map(|_| sc.spawn(|| verify_against(&snap, &rt.prior.chain, &scratch)))
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(verdicts, [Verdict::Valid, Verdict::Valid]);
}
