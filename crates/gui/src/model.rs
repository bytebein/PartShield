//! Lo que la interfaz pide al motor, sin GTK: se puede probar sin pantalla.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;

use anyhow::{anyhow, bail, Context, Result};
use partshield_core::cmd::{Cmd, CommandRecord, Session};
use partshield_core::detect::devices::{self, Disk};
use partshield_core::detect::modes::{assess_with_kernel, KernelFeatures};
use partshield_core::detect::superblock::SuperblockCopies;
use partshield_core::detect::{block_stack, read_all_copies};
use partshield_core::send::multi::SubvolSpec;
use partshield_core::types::{Assessment, BlockStack, HashAlgo, Report, Superblock};
use partshield_core::{backup, backup_raw, partclone_version, BackupOptions, RawOptions};

pub fn list_disks() -> Result<(Vec<Disk>, Vec<CommandRecord>)> {
    let mut s = Session::new(false);
    let disks = devices::list(&mut s)?;
    Ok((disks, s.records))
}

/// Todo lo que se sabe de un Btrfs sin escribir nada.
pub struct DetectInfo {
    pub device: PathBuf,
    pub copies: SuperblockCopies,
    pub superblock: Superblock,
    pub modes: Vec<Assessment>,
    pub stack: Result<BlockStack, String>,
    pub warnings: Vec<String>,
    pub commands: Vec<CommandRecord>,
}

pub fn detect(device: &Path) -> Result<DetectInfo> {
    let mut s = Session::new(false);
    let copies = read_all_copies(device).map_err(|e| {
        let hint = if e.to_string().contains("Permission denied") {
            " (hace falta ejecutar PartShield como root)"
        } else {
            ""
        };
        anyhow!("{e}{hint}")
    })?;
    let superblock = copies.primary().cloned().ok_or_else(|| {
        anyhow!(
            "el superbloque principal de {} no es válido",
            device.display()
        )
    })?;
    let modes = assess_with_kernel(
        &superblock.features,
        partclone_version(&mut s),
        KernelFeatures::from_sysfs().as_ref(),
    );
    let stack = block_stack(&mut s, device).map_err(|e| format!("{e:#}"));
    let warnings = copies.discrepancies();
    Ok(DetectInfo {
        device: device.to_path_buf(),
        copies,
        superblock,
        modes,
        stack,
        warnings,
        commands: s.records,
    })
}

// ------------------------------------------------------------------ copia

/// Dónde monta PartShield lo que necesita, fuera de la vista del usuario.
const RUN_DIR: &str = "/run/partshield";

/// Un subvolumen de `btrfs subvolume list`.
#[derive(Debug, Clone, PartialEq)]
pub struct Subvol {
    pub id: u64,
    pub top_level: u64,
    pub path: String,
}

impl Subvol {
    /// Snapshots de snapper, timeshift y los que deja PartShield: no se
    /// copian por defecto.
    pub fn looks_like_snapshot(&self) -> bool {
        self.path.split('/').any(|c| {
            matches!(
                c,
                ".snapshots" | "@snapshots" | "@.snapshots" | "timeshift-btrfs"
            ) || c.starts_with(".partshield")
        }) || self.path.contains("--partshield-")
    }

    /// Lo que se marca solo: subvolúmenes de primer nivel que no son snapshots.
    pub fn selected_by_default(&self) -> bool {
        self.top_level == 5 && !self.looks_like_snapshot()
    }
}

/// `ID 256 gen 7 top level 5 path @home` → Subvol.
pub fn parse_subvolume_list(out: &str) -> Vec<Subvol> {
    out.lines()
        .filter_map(|l| {
            let id = l
                .strip_prefix("ID ")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()?;
            let (_, rest) = l.split_once(" top level ")?;
            let (top, path) = rest.split_once(" path ")?;
            Some(Subvol {
                id,
                top_level: top.trim().parse().ok()?,
                path: path.trim().to_string(),
            })
        })
        .collect()
}

/// El Btrfs montado entero (subvolid=5) para ver y copiar sus subvolúmenes.
pub struct SourceMount {
    pub mountpoint: PathBuf,
    pub subvolumes: Vec<Subvol>,
}

/// Monta el nivel superior en solo lectura bajo /run/partshield/origen.
/// La copia lo vuelve a montar en escritura justo antes de crear los
/// snapshots (`btrfs send` los necesita de solo lectura, pero crearlos escribe).
pub fn mount_source(device: &Path, fsid: &str) -> Result<SourceMount> {
    let mut s = Session::new(false);
    let mnt = PathBuf::from(RUN_DIR).join("origen").join(fsid);
    std::fs::create_dir_all(&mnt)?;
    if !is_mountpoint(&mut s, &mnt) {
        s.run(
            Cmd::new("mount")
                .arg("-t")
                .arg("btrfs")
                .arg("-o")
                .arg("ro,subvolid=5")
                .arg(device)
                .arg(&mnt),
        )
        .context("no se pudo montar el Btrfs de origen")?;
    }
    let out = s.run(Cmd::new("btrfs").arg("subvolume").arg("list").arg(&mnt))?;
    Ok(SourceMount {
        mountpoint: mnt,
        subvolumes: parse_subvolume_list(&out),
    })
}

fn is_mountpoint(s: &mut Session, path: &Path) -> bool {
    s.run_unchecked(&Cmd::new("mountpoint").arg("-q").arg(path))
        .map(|o| o.success)
        .unwrap_or(false)
}

/// Un sitio donde guardar la copia.
#[derive(Debug, Clone)]
pub struct Destination {
    pub device: PathBuf,
    pub disk: String,
    pub fstype: String,
    pub label: Option<String>,
    pub size: u64,
    /// Si ya está montado en escritura, dónde.
    pub mountpoint: Option<PathBuf>,
}

impl Destination {
    pub fn title(&self) -> String {
        let name = self
            .device
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match &self.label {
            Some(l) => format!("{name} «{l}»"),
            None => name,
        }
    }
}

/// Sistemas de archivos en los que se puede escribir una copia.
const DEST_FSTYPES: [&str; 7] = ["btrfs", "ext4", "ext3", "xfs", "exfat", "vfat", "ntfs"];

/// Volúmenes de otros discos donde guardar la copia: nunca el disco de
/// origen ni el USB de arranque.
pub fn destinations(disks: &[Disk], source: &Path) -> Vec<Destination> {
    let source_disk = disks
        .iter()
        .find(|d| d.path == source || d.volumes.iter().any(|v| v.path == source))
        .map(|d| d.path.clone());
    let mut out = Vec::new();
    for d in disks {
        if Some(&d.path) == source_disk.as_ref() || d.volumes.iter().any(|v| v.is_live_medium()) {
            continue;
        }
        let disk = format!(
            "{} · {}",
            d.model.as_deref().unwrap_or(&d.path.display().to_string()),
            devices::human_size(d.size)
        );
        for v in &d.volumes {
            let Some(fstype) = v.fstype.as_deref().filter(|f| DEST_FSTYPES.contains(f)) else {
                continue;
            };
            out.push(Destination {
                device: v.path.clone(),
                disk: disk.clone(),
                fstype: fstype.to_string(),
                label: v.label.clone(),
                size: v.size,
                mountpoint: v
                    .mountpoints
                    .iter()
                    .find(|m| m.starts_with('/'))
                    .map(PathBuf::from),
            });
        }
    }
    out
}

/// Monta el destino si hace falta y devuelve la carpeta de copias.
pub fn prepare_destination(dest: &Destination, s: &mut Session) -> Result<PathBuf> {
    let root = match &dest.mountpoint {
        Some(m) => m.clone(),
        None => {
            let name = dest
                .device
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "destino".into());
            let mnt = PathBuf::from(RUN_DIR).join("destino").join(name);
            std::fs::create_dir_all(&mnt)?;
            if !is_mountpoint(s, &mnt) {
                s.run(Cmd::new("mount").arg(&dest.device).arg(&mnt))
                    .context("no se pudo montar el destino")?;
            }
            mnt
        }
    };
    Ok(root.join("partshield-copias"))
}

/// Bytes libres en `path` (o en el primer antecesor que exista).
pub fn free_bytes(path: &Path) -> Option<u64> {
    let mut p = path;
    while !p.exists() {
        p = p.parent()?;
    }
    let mut s = Session::new(false);
    let out = s
        .run(Cmd::new("df").arg("--output=avail").arg("-B1").arg(p))
        .ok()?;
    out.lines().nth(1)?.trim().parse().ok()
}

/// Qué copiar.
#[derive(Debug, Clone)]
pub enum Job {
    /// btrfs send de los subvolúmenes elegidos (rutas relativas al nivel
    /// superior; "" es el propio nivel superior).
    Send {
        mount: PathBuf,
        subvolumes: Vec<String>,
        layout: bool,
        keep_snapshot: bool,
    },
    /// Imagen sector a sector del dispositivo entero.
    Raw { device: PathBuf },
}

pub struct JobOptions {
    pub dest: Destination,
    pub zstd_level: i32,
    pub hash: HashAlgo,
}

/// Etiqueta estable de un subvolumen: su ruta, con `/` cambiado por `_`.
pub fn subvol_label(path: &str) -> String {
    if path.is_empty() {
        "nivel-superior".into()
    } else {
        path.replace('/', "_")
    }
}

/// Lanza la copia con su verificación. Bloquea: llámalo fuera del hilo de
/// la interfaz. Cada comando se manda por `progress` antes de ejecutarse.
pub fn run_job(
    job: &Job,
    opts: &JobOptions,
    progress: Sender<String>,
) -> Result<(Report, PathBuf)> {
    let mut s = Session::new(false);
    s.progress = Some(progress);
    let dest_dir = prepare_destination(&opts.dest, &mut s)?;
    std::fs::create_dir_all(&dest_dir)?;
    let mut prep = std::mem::take(&mut s.records);
    let (mut report, path) = match job {
        Job::Raw { device } => backup_raw(
            &mut s,
            &RawOptions {
                device,
                dest_dir: &dest_dir,
                scratch_dir: None,
                zstd_level: opts.zstd_level,
                hash: opts.hash,
                sign_key: None,
            },
        )?,
        Job::Send {
            mount,
            subvolumes,
            layout,
            keep_snapshot,
        } => {
            if subvolumes.is_empty() {
                bail!("no hay ningún subvolumen elegido");
            }
            s.run(Cmd::new("mount").arg("-o").arg("remount,rw").arg(mount))
                .context("no se pudo montar el origen en escritura para crear los snapshots")?;
            prep.append(&mut s.records);
            let labels: Vec<String> = subvolumes.iter().map(|p| subvol_label(p)).collect();
            let sources: Vec<PathBuf> = subvolumes.iter().map(|p| mount.join(p)).collect();
            let specs: Vec<SubvolSpec> = labels
                .iter()
                .zip(&sources)
                .map(|(label, source)| SubvolSpec { label, source })
                .collect();
            let result = backup(
                &mut s,
                &BackupOptions {
                    source: mount,
                    dest_dir: &dest_dir,
                    snapshot_dir: Some(mount),
                    scratch_dir: None,
                    keep_snapshot: *keep_snapshot,
                    zstd_level: opts.zstd_level,
                    parent_report: None,
                    hash: opts.hash,
                    sign_key: None,
                    subvolumes: &specs,
                    capture_layout: *layout,
                    disk: None,
                },
            );
            // Vuelve a solo lectura pase lo que pase.
            let _ = s.run_unchecked(&Cmd::new("mount").arg("-o").arg("remount,ro").arg(mount));
            result?
        }
    };
    // Los comandos de preparación (montajes) también son parte de la copia.
    prep.append(&mut report.commands);
    report.commands = prep;
    Ok((report, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_subvolume_list() {
        let out = "ID 256 gen 1520 top level 5 path @\n\
                   ID 257 gen 1519 top level 5 path @home\n\
                   ID 258 gen 1400 top level 256 path @/var/lib/machines\n\
                   ID 259 gen 1500 top level 5 path @snapshots\n\
                   ID 260 gen 1500 top level 259 path @snapshots/.snapshots/1/snapshot\n\
                   ID 261 gen 1510 top level 5 path my dir with spaces\n";
        let v = parse_subvolume_list(out);
        assert_eq!(v.len(), 6);
        assert_eq!(v[1].path, "@home");
        assert_eq!(v[2].top_level, 256);
        assert_eq!(v[5].path, "my dir with spaces");
        let chosen: Vec<_> = v
            .iter()
            .filter(|s| s.selected_by_default())
            .map(|s| s.path.as_str())
            .collect();
        assert_eq!(chosen, ["@", "@home", "my dir with spaces"]);
    }

    #[test]
    fn labels_are_stable_names() {
        assert_eq!(subvol_label("@home"), "@home");
        assert_eq!(subvol_label("@/var/lib"), "@_var_lib");
        assert_eq!(subvol_label(""), "nivel-superior");
    }

    /// Copia real con loops: Btrfs con @ y @home → ext4. Necesita root;
    /// sin root (o sin loops) no hace nada.
    #[test]
    fn copy_job_end_to_end_on_loops() {
        if !nix_root() || std::env::var_os("PARTSHIELD_GUI_E2E").is_none() {
            eprintln!("omitida: PARTSHIELD_GUI_E2E=1 y root");
            return;
        }
        std::env::set_var("PARTSHIELD_SANDBOX", "1");
        let dir = tempfile::tempdir().unwrap();
        let sh = |c: &str| {
            let o = std::process::Command::new("sh")
                .arg("-c")
                .arg(c)
                .output()
                .unwrap();
            assert!(
                o.status.success(),
                "{c}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            String::from_utf8(o.stdout).unwrap().trim().to_string()
        };
        let d = dir.path().display();
        let src = sh(&format!(
            "truncate -s 1G {d}/src.img && losetup -f --show {d}/src.img"
        ));
        let dst = sh(&format!(
            "truncate -s 2G {d}/dst.img && losetup -f --show {d}/dst.img"
        ));
        let cleanup = |m: &str| {
            let _ = std::process::Command::new("umount").arg(m).status();
        };
        sh(&format!(
            "mkfs.btrfs -q -L demo {src} && mkfs.ext4 -q -L copias {dst}"
        ));
        sh(&format!(
            "m=$(mktemp -d) && mount {src} $m && btrfs -q subvolume create $m/@ $m/@home && \
             mkdir -p $m/@home/ana && echo hola > $m/@home/ana/nota.txt && \
             head -c 3M /dev/urandom > $m/@/datos.bin && umount $m"
        ));
        let fsid = sh(&format!("blkid -s UUID -o value {src}"));
        let m = mount_source(Path::new(&src), &fsid).unwrap();
        let paths: Vec<_> = m.subvolumes.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(paths, ["@", "@home"]);
        let dest = Destination {
            device: PathBuf::from(&dst),
            disk: "loop".into(),
            fstype: "ext4".into(),
            label: None,
            size: 2 << 30,
            mountpoint: None,
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let job = Job::Send {
            mount: m.mountpoint.clone(),
            subvolumes: vec!["@".into(), "@home".into()],
            layout: false,
            keep_snapshot: false,
        };
        let res = run_job(
            &job,
            &JobOptions {
                dest,
                zstd_level: 3,
                hash: HashAlgo::Blake3,
            },
            tx,
        );
        let seen: Vec<String> = rx.try_iter().collect();
        let dmnt = format!(
            "/run/partshield/destino/{}",
            Path::new(&dst).file_name().unwrap().to_string_lossy()
        );
        let (report, path) = res.unwrap();
        cleanup(&m.mountpoint.display().to_string());
        assert!(path.starts_with(&dmnt), "{}", path.display());
        cleanup(&dmnt);
        let _ = sh(&format!("losetup -d {src} {dst}"));
        assert_eq!(report.error, None);
        assert_eq!(report.verdict(), partshield_core::types::Verdict::Valid);
        assert_eq!(report.subvolumes.len(), 2);
        assert!(seen.iter().any(|c| c.starts_with("btrfs send")), "{seen:?}");
        assert!(report.commands[0].command.starts_with("mount"));
    }

    fn nix_root() -> bool {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .map(|o| o.stdout == b"0\n")
            .unwrap_or(false)
    }

    #[test]
    fn destinations_skip_source_disk_and_live_usb() {
        let disks = devices::parse(include_str!("../tests/lsblk-zenbook.json")).unwrap();
        let src = PathBuf::from("/dev/mapper/luks-c0ffee");
        let d = destinations(&disks, &src);
        let devs: Vec<_> = d.iter().map(|x| x.device.display().to_string()).collect();
        assert_eq!(devs, ["/dev/nvme1n1p1"]);
        assert_eq!(d[0].fstype, "ext4");
        assert!(d[0].mountpoint.is_none());
    }
}
