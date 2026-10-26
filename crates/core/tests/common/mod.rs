//! Fixtures compartidas por los tests de punta a punta.
//!
//! - [`e2e_enabled`]: los tests solo corren con `PARTSHIELD_E2E=1` (y exigen
//!   `PARTSHIELD_SANDBOX=1`).
//! - [`only_loop`] / [`sh`] / [`run`]: todo comando que el test lanza por su
//!   cuenta (fuera de `Session`) pasa antes por la comprobación de que los
//!   únicos `/dev/` que nombra son `/dev/loop*`.
//! - [`FsBuilder`] / [`TestFs`]: un Btrfs sobre un archivo disperso y un loop
//!   device en un tempdir, desmontado (`umount -R`) y liberado
//!   (`losetup -d`) en `Drop`, también si el test entra en pánico.
//! - [`content`]: rellenos (incompresibles, compresibles, dispersos,
//!   hardlinks, symlinks, nombres raros, xattrs, permisos, vacíos, muchos
//!   pequeños).
//! - [`snapshot_tree`] / [`diff_trees`]: comparación más estricta que
//!   `verify::compare` (también xattrs, hardlinks, nlink y mtime).

#![allow(dead_code)] // cada binario de test usa una parte distinta

pub mod harness;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

// ------------------------------------------------------------ activación

/// `true` si hay que ejecutar el test. Si no, explica por qué se omite.
pub fn e2e_enabled(test: &str) -> bool {
    if std::env::var_os("PARTSHIELD_E2E").map_or(true, |v| v != "1") {
        eprintln!(
            "{test}: omitido; define PARTSHIELD_E2E=1 (necesita root, loop devices y btrfs-progs)"
        );
        return false;
    }
    assert!(
        std::env::var_os("PARTSHIELD_SANDBOX").is_some_and(|v| v == "1"),
        "{test}: los tests e2e solo corren con PARTSHIELD_SANDBOX=1 exportado"
    );
    assert!(
        Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|o| o.stdout.trim_ascii() == b"0"),
        "{test}: PARTSHIELD_E2E=1 necesita root"
    );
    true
}

pub fn have(program: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {program}"))
        .output()
        .is_ok_and(|o| o.status.success())
}

// ---------------------------------------------------------- solo loops

fn is_real_device(a: &str) -> bool {
    a.starts_with("/dev/")
        && !a.starts_with("/dev/loop")
        && !matches!(
            a,
            "/dev/null" | "/dev/zero" | "/dev/urandom" | "/dev/random"
        )
}

/// Panics if any argument names a `/dev/` path that is not a loop device
/// (also `if=/dev/sda`-style arguments and symlinks such as
/// `/dev/disk/by-uuid/…`, which are resolved first).
pub fn only_loop<S: AsRef<OsStr>>(args: &[S]) {
    for a in args {
        let a = a.as_ref().to_string_lossy();
        for part in a.split('=') {
            let resolved = Path::new(part)
                .canonicalize()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            for candidate in [part, resolved.as_str()] {
                assert!(
                    !is_real_device(candidate),
                    "PARTSHIELD_SANDBOX (tests): `{a}` toca {candidate}; solo se permiten /dev/loop*"
                );
            }
        }
    }
}

/// Runs a command after [`only_loop`], without checking its exit status.
pub fn run<S: AsRef<OsStr>>(program: &str, args: &[S]) -> Output {
    only_loop(&[program]);
    only_loop(args);
    Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("no se pudo ejecutar {program}: {e}"))
}

/// Runs a command after [`only_loop`] and returns its trimmed stdout;
/// panics with stderr on failure.
pub fn sh<S: AsRef<OsStr>>(program: &str, args: &[S]) -> String {
    let out = run(program, args);
    assert!(
        out.status.success(),
        "{program} {:?}: {}",
        args.iter().map(|a| a.as_ref()).collect::<Vec<_>>(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn os(p: &Path) -> &OsStr {
    p.as_os_str()
}

// ---------------------------------------------------------- Btrfs de prueba

#[derive(Debug, Clone)]
pub struct FsBuilder {
    size: u64,
    block_group_tree: bool,
    compress_zstd: bool,
    label: String,
    /// Subvolumes to create, in order, relative to the top level.
    subvolumes: Vec<String>,
}

impl Default for FsBuilder {
    fn default() -> Self {
        Self {
            size: 2 << 30,
            block_group_tree: true,
            compress_zstd: true,
            label: "partshield-test".into(),
            subvolumes: Vec::new(),
        }
    }
}

impl FsBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apparent size of the sparse image file.
    pub fn size(mut self, bytes: u64) -> Self {
        self.size = bytes;
        self
    }

    pub fn block_group_tree(mut self, on: bool) -> Self {
        self.block_group_tree = on;
        self
    }

    pub fn compress_zstd(mut self, on: bool) -> Self {
        self.compress_zstd = on;
        self
    }

    pub fn label(mut self, label: &str) -> Self {
        self.label = label.into();
        self
    }

    /// Adds a subvolume (e.g. `@`, `@home`, `@home/.snapshots`).
    pub fn subvolume(mut self, path: &str) -> Self {
        self.subvolumes.push(path.into());
        self
    }

    /// The usual desktop layout: `@`, `@home` and `@home/.snapshots`.
    pub fn desktop_layout(self) -> Self {
        self.subvolume("@")
            .subvolume("@home")
            .subvolume("@home/.snapshots")
    }

    /// Creates the image in a fresh directory under `parent` (or the
    /// system temp dir), attaches it and mounts the top level.
    pub fn build_in(&self, parent: &Path) -> TestFs {
        let dir = tempfile::Builder::new()
            .prefix("partshield-fs-")
            .tempdir_in(parent)
            .expect("tempdir");
        let image = dir.path().join("disco.img");
        fs::File::create(&image)
            .and_then(|f| f.set_len(self.size))
            .expect("imagen dispersa");
        let mut args: Vec<OsString> = vec!["-q".into(), "-L".into(), self.label.clone().into()];
        if self.block_group_tree {
            args.extend(["-O".into(), "block-group-tree".into()]);
        }
        args.push(image.clone().into());
        sh("mkfs.btrfs", &args);
        let loopdev = sh(
            "losetup",
            &[OsStr::new("--find"), OsStr::new("--show"), os(&image)],
        );
        only_loop(&[&loopdev]);
        let mut me = TestFs {
            dir,
            image,
            loopdev: PathBuf::from(loopdev),
            top: PathBuf::new(),
            mounts: Vec::new(),
            mount_opts: if self.compress_zstd {
                "compress=zstd".into()
            } else {
                "defaults".into()
            },
        };
        let top = me.dir.path().join("top");
        me.mount_at(None, &top);
        me.top = top;
        for sv in &self.subvolumes {
            sh(
                "btrfs",
                &[
                    OsStr::new("subvolume"),
                    OsStr::new("create"),
                    os(&me.top.join(sv)),
                ],
            );
        }
        me
    }

    pub fn build(&self) -> TestFs {
        self.build_in(&std::env::temp_dir())
    }
}

/// A loop-mounted Btrfs. Drop unmounts everything (`umount -R`, newest
/// mount first), detaches the loop device and removes the image.
pub struct TestFs {
    dir: tempfile::TempDir,
    pub image: PathBuf,
    pub loopdev: PathBuf,
    /// Top-level subvolume (id 5) mount.
    pub top: PathBuf,
    mounts: Vec<PathBuf>,
    mount_opts: String,
}

impl TestFs {
    /// Directory holding the image and mountpoints.
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// Mounts `subvol` (or the top level) at `at`, with the builder's
    /// options plus `extra`.
    pub fn mount_subvol(&mut self, subvol: &str, at: &Path, extra: &str) {
        let opts = format!("{},subvol={subvol}{extra}", self.mount_opts);
        fs::create_dir_all(at).unwrap();
        sh(
            "mount",
            &[
                OsStr::new("-o"),
                OsStr::new(&opts),
                os(&self.loopdev),
                os(at),
            ],
        );
        self.mounts.push(at.to_path_buf());
    }

    fn mount_at(&mut self, subvol: Option<&str>, at: &Path) {
        match subvol {
            Some(sv) => self.mount_subvol(sv, at, ""),
            None => {
                fs::create_dir_all(at).unwrap();
                sh(
                    "mount",
                    &[
                        OsStr::new("-o"),
                        OsStr::new(&self.mount_opts),
                        os(&self.loopdev),
                        os(at),
                    ],
                );
                self.mounts.push(at.to_path_buf());
            }
        }
    }

    /// Unmounts everything (the image stays attached).
    pub fn unmount_all(&mut self) {
        while let Some(m) = self.mounts.pop() {
            sh("umount", &[OsStr::new("-R"), os(&m)]);
        }
    }

    /// Mounts the top level again after [`TestFs::unmount_all`].
    pub fn remount_top(&mut self) {
        let top = self.top.clone();
        self.mount_at(None, &top);
    }

    /// `btrfs check --readonly` on the (unmounted) device.
    pub fn check(&mut self) -> Output {
        assert!(self.mounts.is_empty(), "desmonta antes de btrfs check");
        run(
            "btrfs",
            &[
                OsStr::new("check"),
                OsStr::new("--readonly"),
                os(&self.loopdev),
            ],
        )
    }

    pub fn superblock(&self) -> partshield_core::types::Superblock {
        use partshield_core::detect::SuperblockExt;
        partshield_core::types::Superblock::read_from(&self.loopdev).expect("superbloque")
    }

    /// `btrfs filesystem sync` + `sync`, so on-disk trees are current.
    pub fn sync(&self) {
        sh(
            "btrfs",
            &[OsStr::new("filesystem"), OsStr::new("sync"), os(&self.top)],
        );
        sh::<&str>("sync", &[]);
    }
}

impl Drop for TestFs {
    fn drop(&mut self) {
        while let Some(m) = self.mounts.pop() {
            let _ = Command::new("umount").arg("-R").arg(&m).status();
        }
        let dev = self.loopdev.to_string_lossy();
        if dev.starts_with("/dev/loop") {
            let _ = Command::new("losetup")
                .arg("--detach")
                .arg(&self.loopdev)
                .status();
        }
        let _ = fs::remove_file(&self.image);
    }
}

/// Uncompressed vs. on-disk bytes per `compsize` (`None` if not installed).
pub fn compsize(path: &Path) -> Option<(u64, u64)> {
    if !have("compsize") {
        return None;
    }
    let out = sh("compsize", &[OsStr::new("-b"), os(path)]);
    // TOTAL  <perc>  <disk usage>  <uncompressed>  <referenced>
    let total = out.lines().find(|l| l.starts_with("TOTAL"))?;
    let cols: Vec<&str> = total.split_whitespace().collect();
    Some((cols[3].parse().ok()?, cols[2].parse().ok()?))
}

// ------------------------------------------------------------- contenido

pub mod content {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{symlink, PermissionsExt};

    /// Fast deterministic incompressible bytes (xorshift64*).
    pub fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        let mut v = Vec::with_capacity(len + 8);
        while v.len() < len {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            v.extend_from_slice(&x.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes());
        }
        v.truncate(len);
        v
    }

    pub fn big_incompressible(dir: &Path) {
        fs::create_dir_all(dir.join("grandes")).unwrap();
        fs::write(dir.join("grandes/ruido-48M.bin"), noise(48 << 20, 1)).unwrap();
        fs::write(
            dir.join("grandes/ruido-impar.bin"),
            noise((7 << 20) + 13, 2),
        )
        .unwrap();
    }

    /// Writes `mib` MiB of very compressible text.
    pub fn highly_compressible(dir: &Path, mib: usize) {
        fs::create_dir_all(dir.join("compresible")).unwrap();
        let line = b"PartShield nunca da una copia por buena sin restaurarla. 0123456789\n";
        let mut f = fs::File::create(dir.join("compresible/registro.log")).unwrap();
        let block: Vec<u8> = line.iter().copied().cycle().take(1 << 20).collect();
        for _ in 0..mib {
            f.write_all(&block).unwrap();
        }
        fs::write(dir.join("compresible/ceros.bin"), vec![0u8; 8 << 20]).unwrap();
    }

    /// Sparse files: data islands in a large apparent size, a hole at the
    /// end, and a file that is only a hole.
    pub fn sparse(dir: &Path, apparent: u64) {
        use std::os::unix::fs::FileExt;
        fs::create_dir_all(dir.join("dispersos")).unwrap();
        let f = fs::File::create(dir.join("dispersos/islas.img")).unwrap();
        f.set_len(apparent).unwrap();
        for (i, off) in [
            0,
            apparent / 3,
            apparent / 2 + 4096 * 7,
            apparent - (1 << 20),
        ]
        .into_iter()
        .enumerate()
        {
            f.write_all_at(&noise(256 << 10, 10 + i as u64), off)
                .unwrap();
        }
        let g = fs::File::create(dir.join("dispersos/cola-hueca.img")).unwrap();
        g.write_all_at(&noise(64 << 10, 20), 0).unwrap();
        g.set_len(apparent / 4).unwrap();
        fs::File::create(dir.join("dispersos/solo-hueco.img"))
            .unwrap()
            .set_len(apparent / 8)
            .unwrap();
    }

    pub fn hardlinks(dir: &Path) {
        fs::create_dir_all(dir.join("enlaces/otro dir")).unwrap();
        fs::write(dir.join("enlaces/original"), noise(100_000, 30)).unwrap();
        fs::hard_link(dir.join("enlaces/original"), dir.join("enlaces/duro1")).unwrap();
        fs::hard_link(
            dir.join("enlaces/original"),
            dir.join("enlaces/otro dir/duro2"),
        )
        .unwrap();
        fs::write(dir.join("enlaces/pequeño"), "x").unwrap();
        fs::hard_link(dir.join("enlaces/pequeño"), dir.join("enlaces/pequeño-bis")).unwrap();
    }

    pub fn symlinks(dir: &Path) {
        fs::create_dir_all(dir.join("simbolicos/sub")).unwrap();
        fs::write(dir.join("simbolicos/destino.txt"), "destino").unwrap();
        symlink("destino.txt", dir.join("simbolicos/relativo")).unwrap();
        symlink("../destino.txt", dir.join("simbolicos/sub/arriba")).unwrap();
        symlink("/etc/hostname", dir.join("simbolicos/absoluto")).unwrap();
        symlink("no/existe", dir.join("simbolicos/roto")).unwrap();
        symlink("sub", dir.join("simbolicos/a-directorio")).unwrap();
        symlink("bucle", dir.join("simbolicos/bucle")).unwrap();
        let long = "d/".repeat(1000) + "fin";
        symlink(&long, dir.join("simbolicos/largo")).unwrap();
    }

    pub fn odd_names(dir: &Path) {
        let base = dir.join("nombres raros");
        fs::create_dir_all(&base).unwrap();
        for name in [
            "con espacios.txt",
            "  empieza y acaba con espacios  ",
            "ñandú-Ærø-日本語-😀.txt",
            "comillas 'simples' y \"dobles\"",
            "salto\nde línea",
            "tab\there",
            "-empieza-con-guion",
            "*?[glob]",
            "barra\\invertida",
            ".oculto",
            &"n".repeat(255),
        ] {
            fs::write(base.join(name), name.as_bytes()).unwrap();
        }
        fs::create_dir_all(base.join("dir con espacios/sub ñ")).unwrap();
        fs::write(base.join("dir con espacios/sub ñ/x"), "y").unwrap();
        // Bytes that are not valid UTF-8.
        use std::os::unix::ffi::OsStrExt;
        fs::write(base.join(OsStr::from_bytes(b"latin1-\xf1and\xfa")), "l1").unwrap();
    }

    pub fn xattrs(dir: &Path) {
        let base = dir.join("xattrs");
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("con-xattr"), "datos").unwrap();
        fs::write(base.join("binario"), "datos").unwrap();
        let f = base.join("con-xattr");
        sh(
            "setfattr",
            &[
                OsStr::new("-n"),
                OsStr::new("user.comentario"),
                OsStr::new("-v"),
                OsStr::new("hola mundo ñ"),
                f.as_os_str(),
            ],
        );
        sh(
            "setfattr",
            &[OsStr::new("-n"), OsStr::new("user.vacio"), f.as_os_str()],
        );
        sh(
            "setfattr",
            &[
                OsStr::new("-n"),
                OsStr::new("trusted.partshield"),
                OsStr::new("-v"),
                OsStr::new("0x00ff10"),
                f.as_os_str(),
            ],
        );
        let b = base.join("binario");
        let big = format!("0x{}", "ab".repeat(3000));
        sh(
            "setfattr",
            &[
                OsStr::new("-n"),
                OsStr::new("user.grande"),
                OsStr::new("-v"),
                OsStr::new(&big),
                b.as_os_str(),
            ],
        );
        sh(
            "setfattr",
            &[
                OsStr::new("-n"),
                OsStr::new("user.dir"),
                OsStr::new("-v"),
                OsStr::new("en un directorio"),
                base.as_os_str(),
            ],
        );
        if have("setcap") {
            fs::write(base.join("capacidad"), "#!/bin/sh\n").unwrap();
            fs::set_permissions(base.join("capacidad"), fs::Permissions::from_mode(0o755)).unwrap();
            sh(
                "setcap",
                &[
                    OsStr::new("cap_net_raw+ep"),
                    base.join("capacidad").as_os_str(),
                ],
            );
        }
        if have("setfacl") {
            sh(
                "setfacl",
                &[OsStr::new("-m"), OsStr::new("u:1234:rw-"), b.as_os_str()],
            );
            sh(
                "setfacl",
                &[
                    OsStr::new("-d"),
                    OsStr::new("-m"),
                    OsStr::new("g:777:r-x"),
                    base.as_os_str(),
                ],
            );
        }
    }

    /// Distinct modes (setuid/setgid/sticky included) and owners.
    pub fn perms_owners(dir: &Path) {
        use std::os::unix::fs::chown;
        let base = dir.join("permisos");
        fs::create_dir_all(&base).unwrap();
        let files: [(&str, u32, u32, u32); 8] = [
            ("privado", 0o600, 1000, 1000),
            ("ejecutable", 0o755, 0, 0),
            ("sin-permisos", 0o000, 4242, 4243),
            ("setuid", 0o4755, 0, 0),
            ("setgid", 0o2750, 1000, 50),
            ("solo-grupo", 0o060, 65534, 65534),
            ("raro", 0o1777, 123_456, 654_321),
            ("solo-lectura", 0o444, 33, 33),
        ];
        for (name, mode, uid, gid) in files {
            let p = base.join(name);
            fs::write(&p, name).unwrap();
            chown(&p, Some(uid), Some(gid)).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        }
        let sticky = base.join("tmp-pegajoso");
        fs::create_dir(&sticky).unwrap();
        fs::set_permissions(&sticky, fs::Permissions::from_mode(0o1777)).unwrap();
        let locked = base.join("dir-cerrado");
        fs::create_dir(&locked).unwrap();
        fs::write(locked.join("dentro"), "dentro").unwrap();
        chown(&locked, Some(1000), Some(1000)).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
        // A symlink with its own owner.
        symlink("privado", base.join("enlace-ajeno")).unwrap();
        std::os::unix::fs::lchown(base.join("enlace-ajeno"), Some(1000), Some(1000)).unwrap();
    }

    pub fn empty_files(dir: &Path) {
        let base = dir.join("vacios");
        fs::create_dir_all(base.join("dir-vacio")).unwrap();
        fs::create_dir_all(base.join("anidado/vacío/también")).unwrap();
        for i in 0..20 {
            fs::File::create(base.join(format!("vacio-{i}"))).unwrap();
        }
    }

    /// `n` small files spread over directories (inline extents and a
    /// subvolume tree of several levels).
    pub fn many_small(dir: &Path, n: usize) {
        let base = dir.join("pequeños");
        for i in 0..n {
            let d = base.join(format!("d{:03}", i % 200));
            if i < 200 {
                fs::create_dir_all(&d).unwrap();
            }
            fs::write(d.join(format!("f{i}")), format!("archivo pequeño {i}\n")).unwrap();
        }
    }

    /// Everything above at a moderate size.
    pub fn everything(dir: &Path) {
        big_incompressible(dir);
        highly_compressible(dir, 64);
        sparse(dir, 256 << 20);
        hardlinks(dir);
        symlinks(dir);
        odd_names(dir);
        xattrs(dir);
        perms_owners(dir);
        empty_files(dir);
        many_small(dir, 5000);
    }

    /// Leaves an 8 KiB file in each of `n` new data chunks, so the chunk
    /// tree no longer fits in one leaf (chunk root becomes an interior
    /// node, as on a real disk of hundreds of GB). The rest of each chunk
    /// is taken with `fallocate` (writes nothing) and freed afterwards.
    /// Needs an image of at least `n` GiB (sparse: costs a few MB).
    pub fn many_chunks(fs_top: &Path, dir: &Path, n: usize) {
        let anchors = dir.join("anclas");
        let filler = fs_top.join("hueco");
        fs::create_dir_all(&anchors).unwrap();
        fs::create_dir_all(&filler).unwrap();
        for i in 0..n {
            fs::write(anchors.join(format!("a{i}")), noise(8192, 1000 + i as u64)).unwrap();
            fs::File::open(&anchors).unwrap().sync_all().unwrap();
            sh::<&str>("sync", &[]);
            sh(
                "fallocate",
                &[
                    OsStr::new("-l"),
                    OsStr::new("1G"),
                    filler.join(format!("h{i}")).as_os_str(),
                ],
            );
        }
        fs::remove_dir_all(&filler).unwrap();
    }
}

// --------------------------------------------------- comparación estricta

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    File { size: u64, hash: String },
    Dir,
    Symlink(PathBuf),
    Other(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: Kind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    /// Seconds and nanoseconds; directories excluded (see `snapshot_tree`).
    pub mtime: Option<(i64, i64)>,
    pub xattrs: BTreeMap<String, String>,
    /// Allocated bytes (`st_blocks * 512`), informative only.
    pub allocated: u64,
}

pub struct Tree {
    pub entries: BTreeMap<PathBuf, Entry>,
    /// Groups of paths sharing an inode (hardlinks), sorted.
    pub link_groups: BTreeSet<Vec<PathBuf>>,
}

/// Reads every entry under `root` (not following symlinks), skipping
/// any path in `exclude` (relative) and everything under it.
pub fn snapshot_tree(root: &Path, exclude: &[&str]) -> Tree {
    let xattrs = read_xattrs(root);
    let mut entries = BTreeMap::new();
    let mut inodes: BTreeMap<u64, Vec<PathBuf>> = BTreeMap::new();
    let walker = walkdir::WalkDir::new(root)
        .follow_links(false)
        .min_depth(1)
        .into_iter()
        .filter_entry(|e| {
            let rel = e.path().strip_prefix(root).unwrap();
            !exclude.iter().any(|x| rel == Path::new(x))
        });
    for item in walker {
        let item = item.unwrap();
        let md = item.path().symlink_metadata().unwrap();
        let ft = md.file_type();
        let rel = item.path().strip_prefix(root).unwrap().to_path_buf();
        let kind = if ft.is_symlink() {
            Kind::Symlink(fs::read_link(item.path()).unwrap())
        } else if ft.is_dir() {
            Kind::Dir
        } else if ft.is_file() {
            let mut h = blake3::Hasher::new();
            h.update_reader(fs::File::open(item.path()).unwrap())
                .unwrap();
            Kind::File {
                size: md.len(),
                hash: h.finalize().to_hex().to_string(),
            }
        } else {
            Kind::Other(md.mode() & 0o170000)
        };
        if !ft.is_dir() && md.nlink() > 1 {
            inodes.entry(md.ino()).or_default().push(rel.clone());
        }
        entries.insert(
            rel.clone(),
            Entry {
                mtime: (!ft.is_dir()).then_some((md.mtime(), md.mtime_nsec())),
                kind,
                mode: md.mode() & 0o7777,
                uid: md.uid(),
                gid: md.gid(),
                nlink: if ft.is_dir() { 0 } else { md.nlink() },
                xattrs: xattrs.get(&rel).cloned().unwrap_or_default(),
                allocated: md.blocks() * 512,
            },
        );
    }
    let link_groups = inodes
        .into_values()
        .map(|mut v| {
            v.sort();
            v
        })
        .collect();
    Tree {
        entries,
        link_groups,
    }
}

/// All xattrs under `root`, via `getfattr -R` (hex-encoded values).
fn read_xattrs(root: &Path) -> BTreeMap<PathBuf, BTreeMap<String, String>> {
    assert!(have("getfattr"), "falta getfattr (paquete attr)");
    only_loop(&[root]);
    let out = Command::new("getfattr")
        .args(["-R", "-P", "-h", "-d", "-m", "-", "-e", "hex", "."])
        .current_dir(root)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let mut map: BTreeMap<PathBuf, BTreeMap<String, String>> = BTreeMap::new();
    let mut current: Option<PathBuf> = None;
    for line in text.lines() {
        if let Some(name) = line.strip_prefix("# file: ") {
            current = Some(PathBuf::from(unescape_getfattr(
                name.trim_start_matches("./"),
            )));
        } else if let (Some(cur), Some((k, v))) = (&current, line.split_once('=')) {
            map.entry(cur.clone())
                .or_default()
                .insert(k.to_string(), v.to_string());
        } else if let (Some(cur), false) = (&current, line.is_empty()) {
            // Attribute with an empty value prints without `=`.
            map.entry(cur.clone())
                .or_default()
                .insert(line.to_string(), String::new());
        }
    }
    map
}

/// getfattr escapes newlines, backslashes and non-printable bytes as `\ooo`.
fn unescape_getfattr(s: &str) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 4 <= b.len() && b[i + 1..i + 4].iter().all(u8::is_ascii_digit) {
            let n = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 4]).unwrap(), 8).unwrap();
            out.push(n);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    OsString::from_vec(out)
}

/// Every difference between two trees (empty when identical): content,
/// type, mode, owner, symlink target, nlink, file mtime, xattrs and
/// hardlink groups.
pub fn diff_trees(expected: &Tree, actual: &Tree) -> Vec<String> {
    let mut d = Vec::new();
    for (p, a) in &expected.entries {
        match actual.entries.get(p) {
            None => d.push(format!("falta: {}", p.display())),
            Some(b) => {
                let mut what = Vec::new();
                if a.kind != b.kind {
                    what.push(format!("{:?} → {:?}", a.kind, b.kind));
                }
                if a.mode != b.mode {
                    what.push(format!("modo {:o} → {:o}", a.mode, b.mode));
                }
                if (a.uid, a.gid) != (b.uid, b.gid) {
                    what.push(format!("dueño {}:{} → {}:{}", a.uid, a.gid, b.uid, b.gid));
                }
                if a.nlink != b.nlink {
                    what.push(format!("nlink {} → {}", a.nlink, b.nlink));
                }
                if a.mtime != b.mtime {
                    what.push(format!("mtime {:?} → {:?}", a.mtime, b.mtime));
                }
                if a.xattrs != b.xattrs {
                    what.push(format!("xattrs {:?} → {:?}", a.xattrs, b.xattrs));
                }
                if !what.is_empty() {
                    d.push(format!("{}: {}", p.display(), what.join("; ")));
                }
            }
        }
    }
    for p in actual
        .entries
        .keys()
        .filter(|p| !expected.entries.contains_key(*p))
    {
        d.push(format!("sobra: {}", p.display()));
    }
    if expected.link_groups != actual.link_groups {
        d.push(format!(
            "hardlinks: {:?} → {:?}",
            expected.link_groups, actual.link_groups
        ));
    }
    d
}

/// Panics listing the first differences if the trees differ.
pub fn assert_same_tree(expected: &Path, actual: &Path, exclude: &[&str]) -> Tree {
    let a = snapshot_tree(expected, exclude);
    let b = snapshot_tree(actual, exclude);
    let d = diff_trees(&a, &b);
    assert!(
        d.is_empty(),
        "{} diferencias entre {} y {}:\n{}",
        d.len(),
        expected.display(),
        actual.display(),
        d.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
    assert!(
        !a.entries.is_empty(),
        "árbol vacío: la comparación no comprobaría nada"
    );
    a
}

// ------------------------------------------------------ loop sin formato

/// A sparse image attached to a loop device, with no filesystem made by
/// us (a restore target for partclone). Drop unmounts and detaches.
pub struct RawLoop {
    dir: tempfile::TempDir,
    pub image: PathBuf,
    pub loopdev: PathBuf,
    mounts: Vec<PathBuf>,
}

impl RawLoop {
    pub fn new(parent: &Path, size: u64) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("partshield-raw-")
            .tempdir_in(parent)
            .unwrap();
        let image = dir.path().join("crudo.img");
        fs::File::create(&image).unwrap().set_len(size).unwrap();
        let dev = sh(
            "losetup",
            &[OsStr::new("--find"), OsStr::new("--show"), os(&image)],
        );
        only_loop(&[&dev]);
        RawLoop {
            dir,
            image,
            loopdev: PathBuf::from(dev),
            mounts: Vec::new(),
        }
    }

    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// Tries a read-only mount; returns the mount output either way.
    pub fn try_mount_ro(&mut self) -> (Output, PathBuf) {
        let at = self.dir.path().join("montado");
        fs::create_dir_all(&at).unwrap();
        let out = run(
            "mount",
            &[
                OsStr::new("-o"),
                OsStr::new("ro"),
                os(&self.loopdev),
                os(&at),
            ],
        );
        if out.status.success() {
            self.mounts.push(at.clone());
        }
        (out, at)
    }
}

impl Drop for RawLoop {
    fn drop(&mut self) {
        while let Some(m) = self.mounts.pop() {
            let _ = Command::new("umount").arg("-R").arg(&m).status();
        }
        if self.loopdev.to_string_lossy().starts_with("/dev/loop") {
            let _ = Command::new("losetup")
                .arg("--detach")
                .arg(&self.loopdev)
                .status();
        }
    }
}

/// Btrfs with BLOCK_GROUP_TREE whose chunk tree and subvolume tree have
/// several levels (see [`content::many_chunks`]): the shape of a real
/// disk of hundreds of GB, where partclone < 0.3.50 can drop the chunk
/// root. Content lives in the `datos` subvolume.
pub fn multilevel_fs(parent: &Path) -> TestFs {
    let fs = FsBuilder::new()
        .size(250 << 30) // disperso: en el host ocupa unos MB
        .label("origen")
        .subvolume("datos")
        .build_in(parent);
    let datos = fs.top.join("datos");
    content::many_chunks(&fs.top, &datos, 170);
    content::big_incompressible(&datos);
    content::many_small(&datos, 20_000);
    content::hardlinks(&datos);
    content::xattrs(&datos);
    fs.sync();
    let sb = fs.superblock();
    assert!(
        sb.chunk_root_level >= 1,
        "el chunk tree debía tener varios niveles (level {})",
        sb.chunk_root_level
    );
    fs
}
