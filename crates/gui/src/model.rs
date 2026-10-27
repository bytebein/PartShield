//! Lo que la interfaz pide al motor, sin GTK: se puede probar sin pantalla.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;

use anyhow::{anyhow, bail, Context, Result};
use partshield_core::cmd::{Cmd, CommandRecord, Session};
use partshield_core::detect::devices::{self, Disk, Volume};
use partshield_core::detect::modes::{assess_with_kernel, KernelFeatures};
use partshield_core::detect::superblock::SuperblockCopies;
use partshield_core::detect::SuperblockExt;
use partshield_core::detect::{block_stack, read_all_copies};
use partshield_core::send::multi::SubvolSpec;
use partshield_core::types::{Assessment, BlockStack, HashAlgo, Mode, Report, Superblock};
use partshield_core::{backup, backup_raw, partclone_version, BackupOptions, RawOptions};

pub fn list_disks() -> Result<(Vec<Disk>, Vec<CommandRecord>)> {
    // Para capturas: discos de un JSON de `lsblk -J -b` en vez de los reales.
    if let Some(p) = std::env::var_os("PARTSHIELD_GUI_LSBLK") {
        return Ok((devices::parse(&std::fs::read_to_string(p)?)?, Vec::new()));
    }
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

/// Volúmenes de otros discos donde guardar la copia: nunca un disco de
/// origen ni el USB de arranque.
pub fn destinations(disks: &[Disk], sources: &[PathBuf]) -> Vec<Destination> {
    let source_disks: Vec<&PathBuf> = disks
        .iter()
        .filter(|d| {
            sources
                .iter()
                .any(|s| *s == d.path || d.volumes.iter().any(|v| v.path == *s))
        })
        .map(|d| &d.path)
        .collect();
    let mut out = Vec::new();
    for d in disks {
        if source_disks.contains(&&d.path) || d.volumes.iter().any(|v| v.is_live_medium()) {
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
    // Los montajes de preparación se quedan en la sesión: `backup` y
    // `backup_raw` los guardan en el informe junto con el resto.
    let dest_dir = prepare_destination(&opts.dest, &mut s)?;
    std::fs::create_dir_all(&dest_dir)?;
    let (report, path) = match job {
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
            // Vuelve a solo lectura pase lo que pase. El informe ya está
            // escrito (nunca se sobrescribe), así que un fallo aquí solo puede
            // ir al informe que muestra la interfaz.
            let ro = s.run_unchecked(&Cmd::new("mount").arg("-o").arg("remount,ro").arg(mount));
            let (mut report, path) = result?;
            report.commands.append(&mut s.records);
            if !ro.as_ref().is_ok_and(|o| o.success) {
                let why = match ro {
                    Ok(o) => o.stderr.trim().to_string(),
                    Err(e) => format!("{e:#}"),
                };
                report.warnings.push(format!(
                    "el origen sigue montado en escritura en {}: no se pudo volver a solo \
                     lectura ({why}). Desmóntalo (umount {}) antes de seguir; este aviso \
                     no está en el informe guardado, que se escribió antes",
                    mount.display(),
                    mount.display()
                ));
            }
            (report, path)
        }
    };
    Ok((report, path))
}

// ------------------------------------------------------------ modo sencillo

/// Nombre para personas: «Disco interno NVMe · Samsung 1 TB».
pub fn disk_title(d: &Disk) -> String {
    let kind = match (d.kind.as_str(), d.transport.as_deref()) {
        ("loop", _) => "Disco de pruebas",
        (_, Some("usb")) => "Disco USB",
        (_, Some("nvme")) => "Disco interno NVMe",
        _ if d.removable => "Disco extraíble",
        _ => "Disco interno",
    };
    match &d.model {
        Some(m) => format!("{kind} · {} · {}", m.trim(), devices::human_size(d.size)),
        None => format!("{kind} · {}", devices::human_size(d.size)),
    }
}

/// Qué es una partición, dicho para personas: «Windows (NTFS) «Datos»».
pub fn volume_title(v: &Volume) -> String {
    let small = v.size < (2 << 30);
    let what = match v.fstype.as_deref() {
        Some("ntfs") if small => "Recuperación de Windows",
        Some("ntfs") => "Windows (NTFS)",
        Some("vfat") if small => "Arranque (EFI)",
        Some("vfat" | "exfat") => "Datos (FAT)",
        Some("btrfs") => "Linux (Btrfs)",
        Some(f @ ("ext4" | "ext3" | "ext2" | "xfs")) => {
            return with_label(format!("Linux ({f})"), v);
        }
        Some("swap") => "Memoria de intercambio (swap)",
        Some("crypto_LUKS") => "Cifrada (LUKS)",
        Some(f) => return with_label(f.to_string(), v),
        None => "Sin formato",
    };
    with_label(what.to_string(), v)
}

fn with_label(s: String, v: &Volume) -> String {
    match &v.label {
        Some(l) if !l.is_empty() => format!("{s} «{l}»"),
        _ => s,
    }
}

/// Lo que se puede marcar en el modo sencillo: discos con sus particiones
/// de primer nivel. Nunca el USB de arranque; los loops solo en pruebas.
pub fn basic_disks(disks: &[Disk], show_loops: bool) -> Vec<&Disk> {
    disks
        .iter()
        .filter(|d| {
            !d.volumes
                .iter()
                .any(|v| v.is_live_medium() || v.is_live_system())
        })
        .filter(|d| show_loops || d.kind != "loop")
        .filter(|d| d.volumes.iter().any(|v| v.depth == 0))
        .collect()
}

/// El disco que se marca entero al abrir: el primer disco interno.
pub fn default_disk(disks: &[&Disk]) -> Option<PathBuf> {
    disks
        .iter()
        .find(|d| !d.removable && d.transport.as_deref() != Some("usb"))
        .map(|d| d.path.clone())
}

/// Marcada al marcar el disco entero. La swap no: se rehace sola.
pub fn checked_with_disk(v: &Volume) -> bool {
    v.fstype.as_deref() != Some("swap")
}

/// Una parte de la copia en el modo sencillo.
#[derive(Debug, Clone)]
pub struct PlanItem {
    /// Lo que ve la persona: «Windows (NTFS) · 200 GiB».
    pub title: String,
    pub device: PathBuf,
    pub btrfs: bool,
}

impl PlanItem {
    pub fn new(v: &Volume) -> Self {
        Self {
            title: format!("{} · {}", volume_title(v), devices::human_size(v.size)),
            device: v.path.clone(),
            btrfs: v.is_btrfs(),
        }
    }

    /// Lo que puede ocupar la copia, antes de comprimir: lo usado en un
    /// Btrfs; la partición entera en el resto (imagen sector a sector).
    pub fn max_bytes(&self, size: u64) -> u64 {
        if self.btrfs {
            Superblock::read_from(&self.device)
                .map(|sb| sb.bytes_used)
                .unwrap_or(size)
        } else {
            size
        }
    }
}

/// Lo que va pasando mientras se copia, para la barra de progreso.
pub enum PlanEvent {
    /// Empieza la parte `index` (desde 0).
    Part(usize),
    /// Comando que se va a ejecutar.
    Command(String),
    /// Ha terminado la parte `index`.
    Done(usize, Result<(Report, PathBuf), String>),
    /// Tabla de particiones guardada (o por qué no).
    Table(Result<PathBuf, String>),
}

/// Copia y verifica cada parte, una detrás de otra. Un fallo en una no
/// para las demás: cada una tiene su propio veredicto. Si se copia el disco
/// entero, guarda antes su tabla de particiones (`sfdisk --dump`).
pub fn run_plan(
    items: &[PlanItem],
    whole_disks: &[PathBuf],
    dest: &Destination,
    events: Sender<PlanEvent>,
) {
    for disk in whole_disks {
        let r = save_partition_table(disk, dest).map_err(|e| format!("{e:#}"));
        let _ = events.send(PlanEvent::Table(r));
    }
    for (i, item) in items.iter().enumerate() {
        let _ = events.send(PlanEvent::Part(i));
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let fwd = {
            let events = events.clone();
            std::thread::spawn(move || {
                for c in rx {
                    let _ = events.send(PlanEvent::Command(c));
                }
            })
        };
        let r = run_item(item, dest, tx).map_err(|e| format!("{e:#}"));
        let _ = fwd.join();
        let _ = events.send(PlanEvent::Done(i, r));
    }
}

/// Btrfs por `btrfs send` (solo datos, todos los subvolúmenes que no son
/// snapshots) si es seguro; si no, y para todo lo demás, imagen sector a
/// sector, que vale para cualquier contenido y se compara bit a bit.
fn run_item(item: &PlanItem, dest: &Destination, tx: Sender<String>) -> Result<(Report, PathBuf)> {
    let opts = JobOptions {
        dest: dest.clone(),
        zstd_level: 3,
        hash: HashAlgo::Blake3,
    };
    let raw = Job::Raw {
        device: item.device.clone(),
    };
    if !item.btrfs {
        return run_job(&raw, &opts, tx);
    }
    let info = detect(&item.device)?;
    let allowed = |m: Mode| info.modes.iter().any(|a| a.mode == m && a.allowed);
    if !allowed(Mode::Send) {
        if allowed(Mode::Raw) {
            return run_job(&raw, &opts, tx);
        }
        bail!("ningún modo de copia es seguro para este Btrfs; míralo en el modo avanzado");
    }
    let m = mount_source(&item.device, &info.superblock.fsid)?;
    let mut subvolumes: Vec<String> = m
        .subvolumes
        .iter()
        .filter(|s| s.selected_by_default())
        .map(|s| s.path.clone())
        .collect();
    if m.subvolumes.is_empty() {
        subvolumes.push(String::new());
    }
    let job = Job::Send {
        mount: m.mountpoint.clone(),
        subvolumes,
        layout: true,
        keep_snapshot: false,
    };
    let r = run_job(&job, &opts, tx);
    let _ = Session::new(false).run_unchecked(&Cmd::new("umount").arg(&m.mountpoint));
    r
}

fn save_partition_table(disk: &Path, dest: &Destination) -> Result<PathBuf> {
    let mut s = Session::new(false);
    let dir = prepare_destination(dest, &mut s)?;
    std::fs::create_dir_all(&dir)?;
    let dump = s.run(Cmd::new("sfdisk").arg("--dump").arg(disk))?;
    let name = disk
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "disco".into());
    let path = dir.join(format!(
        "{name}-{}.sfdisk",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    ));
    std::fs::write(&path, dump)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_mode_hides_live_usb_and_picks_internal_disk() {
        let disks = devices::parse(include_str!("../tests/lsblk-zenbook.json")).unwrap();
        let shown = basic_disks(&disks, false);
        let paths: Vec<_> = shown.iter().map(|d| d.path.display().to_string()).collect();
        assert_eq!(paths, ["/dev/nvme0n1", "/dev/nvme1n1"]);
        assert_eq!(default_disk(&shown), Some(PathBuf::from("/dev/nvme0n1")));
        assert_eq!(
            disk_title(shown[0]),
            "Disco interno NVMe · Samsung SSD 980 PRO 1TB · 954 GiB"
        );
        let titles: Vec<_> = shown[0]
            .volumes
            .iter()
            .filter(|v| v.depth == 0)
            .map(volume_title)
            .collect();
        assert_eq!(titles, ["Arranque (EFI)", "Cifrada (LUKS)"]);
    }

    #[test]
    fn friendly_names_for_common_partitions() {
        let v = |fstype: Option<&str>, size: u64, label: Option<&str>| Volume {
            path: PathBuf::from("/dev/x"),
            kind: "part".into(),
            depth: 0,
            size,
            fstype: fstype.map(String::from),
            label: label.map(String::from),
            uuid: None,
            mountpoints: vec![],
        };
        let gib = 1u64 << 30;
        assert_eq!(
            volume_title(&v(Some("ntfs"), 200 * gib, None)),
            "Windows (NTFS)"
        );
        assert_eq!(
            volume_title(&v(Some("ntfs"), gib / 2, None)),
            "Recuperación de Windows"
        );
        assert_eq!(
            volume_title(&v(Some("btrfs"), 600 * gib, Some("arch"))),
            "Linux (Btrfs) «arch»"
        );
        assert_eq!(
            volume_title(&v(Some("ext4"), 9 * gib, None)),
            "Linux (ext4)"
        );
        assert_eq!(volume_title(&v(None, gib, None)), "Sin formato");
        assert!(!checked_with_disk(&v(Some("swap"), gib, None)));
        assert!(checked_with_disk(&v(Some("ntfs"), gib, None)));
    }

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
        // El informe guardado también lleva los montajes de preparación
        // (se lee antes de desmontar el destino).
        let saved = std::fs::read_to_string(&path).unwrap_or_default();
        cleanup(&m.mountpoint.display().to_string());
        assert!(path.starts_with(&dmnt), "{}", path.display());
        cleanup(&dmnt);
        let _ = sh(&format!("losetup -d {src} {dst}"));
        assert_eq!(report.error, None);
        assert_eq!(report.verdict(), partshield_core::types::Verdict::Valid);
        assert_eq!(report.subvolumes.len(), 2);
        assert!(seen.iter().any(|c| c.starts_with("btrfs send")), "{seen:?}");
        assert!(report.commands[0].command.starts_with("mount"));
        assert!(
            saved.contains("remount,rw"),
            "falta el montaje en el informe guardado"
        );
    }

    /// Modo sencillo con loops: disco con tabla GPT, una ext4 (imagen sector
    /// a sector) y un Btrfs (send) → ext4. Necesita root y
    /// PARTSHIELD_GUI_E2E=1.
    #[test]
    fn whole_disk_plan_end_to_end_on_loops() {
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
            "truncate -s 600M {d}/src.img && \
             printf 'label: gpt\\n,64M\\n,\\n' | sfdisk -q {d}/src.img && \
             losetup -f -P --show {d}/src.img"
        ));
        let dst = sh(&format!(
            "truncate -s 2G {d}/dst.img && losetup -f --show {d}/dst.img"
        ));
        // Si el kernel no crea /dev/loopNpM (sin udev ni tablas GPT, como
        // en algunas VM), cada partición va a su propio loop con --offset.
        let part = |n: usize| -> String {
            let node = format!("{src}p{n}");
            if Path::new(&node).exists() {
                return node;
            }
            let (start, size) = {
                let j = sh(&format!("sfdisk -J {d}/src.img"));
                let v: serde_json::Value = serde_json::from_str(&j).unwrap();
                let p = &v["partitiontable"]["partitions"][n - 1];
                (p["start"].as_u64().unwrap(), p["size"].as_u64().unwrap())
            };
            sh(&format!(
                "losetup -f --show --offset {} --sizelimit {} {d}/src.img",
                start * 512,
                size * 512
            ))
        };
        let (p1, p2) = (part(1), part(2));
        sh(&format!(
            "mkfs.ext4 -q -L arranque {p1} && mkfs.btrfs -q -L linux {p2} && \
             mkfs.ext4 -q -L copias {dst} && \
             m=$(mktemp -d) && mount {p2} $m && btrfs -q subvolume create $m/@ && \
             head -c 2M /dev/urandom > $m/@/datos.bin && umount $m"
        ));
        let vol = |path: &str, fstype: &str, size: u64| Volume {
            path: PathBuf::from(path),
            kind: "part".into(),
            depth: 0,
            size,
            fstype: Some(fstype.into()),
            label: None,
            uuid: None,
            mountpoints: vec![],
        };
        let items = [
            PlanItem::new(&vol(&p1, "ext4", 64 << 20)),
            PlanItem::new(&vol(&p2, "btrfs", 535 << 20)),
        ];
        let dest = Destination {
            device: PathBuf::from(&dst),
            disk: "loop".into(),
            fstype: "ext4".into(),
            label: None,
            size: 2 << 30,
            mountpoint: None,
        };
        let (tx, rx) = std::sync::mpsc::channel();
        run_plan(&items, &[PathBuf::from(&src)], &dest, tx);
        let mut done = Vec::new();
        let mut table = None;
        let mut commands = 0;
        for ev in rx.try_iter() {
            match ev {
                PlanEvent::Done(i, r) => done.push((i, r)),
                PlanEvent::Table(t) => table = Some(t),
                PlanEvent::Command(_) => commands += 1,
                PlanEvent::Part(_) => {}
            }
        }
        let dmnt = format!(
            "/run/partshield/destino/{}",
            Path::new(&dst).file_name().unwrap().to_string_lossy()
        );
        let table_text = table
            .as_ref()
            .and_then(|t| t.as_ref().ok())
            .map(|p| std::fs::read_to_string(p).unwrap_or_default());
        let _ = std::process::Command::new("umount").arg(&dmnt).status();
        let _ = sh(&format!("losetup -d {src} {dst}"));
        for p in [&p1, &p2] {
            if !p.starts_with(&src) {
                let _ = sh(&format!("losetup -d {p}"));
            }
        }
        assert!(table_text.unwrap().contains("label: gpt"));
        assert!(commands > 0);
        assert_eq!(done.len(), 2);
        for (i, r) in &done {
            let (report, _) = r.as_ref().unwrap_or_else(|e| panic!("parte {i}: {e}"));
            assert_eq!(report.error, None, "parte {i}");
            // ext4 pasa por e2fsck y Btrfs por btrfs check: las dos válidas.
            assert_eq!(
                report.verdict(),
                partshield_core::types::Verdict::Valid,
                "parte {i}: {:#?}",
                report.verification
            );
        }
        assert_eq!(
            done[1].1.as_ref().unwrap().0.mode,
            partshield_core::types::Mode::Send
        );
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
        let d = destinations(&disks, &[src]);
        let devs: Vec<_> = d.iter().map(|x| x.device.display().to_string()).collect();
        assert_eq!(devs, ["/dev/nvme1n1p1"]);
        assert_eq!(d[0].fstype, "ext4");
        assert!(d[0].mountpoint.is_none());
    }
}
