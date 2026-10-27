//! Disposición del disco: lo que un sistema necesita para arrancar y no
//! está en ningún subvolumen.
//!
//! - el UUID del Btrfs (lo citan `/etc/fstab` y el cargador de arranque),
//! - la tabla de particiones GPT (`sgdisk --backup`, más `sfdisk --dump`
//!   como texto legible),
//! - la partición EFI, como imagen comprimida con zstd y con hash.
//!
//! La ESP se lee y se escribe por desplazamiento sobre el disco (con `dd`
//! a través de [`Session`]), así que no hace falta que existan los nodos de
//! partición (`/dev/loop0p1`…) ni que el kernel sepa leer la tabla.
//!
//! La restauración comprueba todos los hashes antes de escribir nada y
//! vuelve a leer la ESP escrita para compararla.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::{check_digest, compress_hashed, decompress_into};
use crate::cmd::{guard_path, Cmd, Session};
use crate::detect::blockdev::mounts_below;
use crate::types::{Digest, DiskLayout, HashAlgo, Hasher, StreamRef};

/// Tipo GPT de la partición de sistema EFI.
pub const ESP_GPT_TYPE: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
/// Tipo MBR de la partición de sistema EFI.
pub const ESP_MBR_TYPE: &str = "ef";

// ------------------------------------------------------- tabla (sfdisk)

#[derive(Debug, Deserialize)]
struct SfdiskJson {
    partitiontable: PartTable,
}

/// Tabla de particiones tal como la da `sfdisk --json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PartTable {
    pub label: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default = "default_sector")]
    pub sectorsize: u64,
    #[serde(default)]
    pub partitions: Vec<Partition>,
}

fn default_sector() -> u64 {
    512
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Partition {
    pub node: String,
    pub start: u64,
    pub size: u64,
    #[serde(rename = "type")]
    pub ptype: String,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

impl Partition {
    pub fn is_esp(&self) -> bool {
        self.ptype.eq_ignore_ascii_case(ESP_GPT_TYPE)
            || self.ptype.eq_ignore_ascii_case(ESP_MBR_TYPE)
    }
}

impl PartTable {
    pub fn parse(json: &str) -> Result<Self> {
        Ok(serde_json::from_str::<SfdiskJson>(json)
            .context("leyendo la salida de `sfdisk --json`")?
            .partitiontable)
    }

    /// Primera partición EFI y su (desplazamiento, longitud) en bytes.
    pub fn esp(&self) -> Option<(&Partition, u64, u64)> {
        self.partitions
            .iter()
            .find(|p| p.is_esp())
            .map(|p| (p, p.start * self.sectorsize, p.size * self.sectorsize))
    }
}

pub fn read_table(s: &mut Session, disk: &Path) -> Result<PartTable> {
    let out = s
        .run(Cmd::new("sfdisk").arg("--json").arg(disk))
        .with_context(|| {
            format!(
                "{} no tiene una tabla de particiones legible",
                disk.display()
            )
        })?;
    PartTable::parse(&out)
}

// ---------------------------------------------------------- dispositivos

/// `blkid -p -o export` → (TYPE, UUID).
fn parse_blkid(out: &str) -> (Option<String>, Option<String>) {
    let get = |k: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(k)?.strip_prefix('='))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    (get("TYPE"), get("UUID"))
}

/// Sistema de archivos y UUID leídos del superbloque (sin caché de blkid).
pub fn probe(s: &mut Session, dev: &Path) -> Result<(Option<String>, Option<String>)> {
    guard_path(dev)?;
    let out = s.run_unchecked(&Cmd::new("blkid").arg("-p").arg("-o").arg("export").arg(dev))?;
    // blkid sale con 2 si no reconoce nada.
    match out.code {
        Some(0) => Ok(parse_blkid(&out.stdout)),
        Some(2) => Ok((None, None)),
        _ => bail!("`blkid` falló con {}: {}", dev.display(), out.stderr.trim()),
    }
}

/// `lsblk -rns -o PATH,TYPE <dev>` lista el dispositivo y luego aquello de
/// lo que depende; el disco es el primer `disk`/`loop` tras la primera línea.
fn parse_parent_disk(out: &str) -> Option<PathBuf> {
    out.lines().skip(1).find_map(|l| {
        let mut it = l.split_whitespace();
        let (path, kind) = (it.next()?, it.next()?);
        matches!(kind, "disk" | "loop").then(|| PathBuf::from(path))
    })
}

/// Disco que contiene `part`, si `part` es una partición.
pub fn parent_disk(s: &mut Session, part: &Path) -> Result<Option<PathBuf>> {
    let out = s.run(
        Cmd::new("lsblk")
            .arg("-r")
            .arg("-n")
            .arg("-s")
            .arg("-o")
            .arg("PATH,TYPE")
            .arg(part),
    )?;
    Ok(parse_parent_disk(&out))
}

fn ensure_unmounted(s: &mut Session, dev: &Path) -> Result<()> {
    // También lo que cuelga por LUKS o LVM (`/dev/mapper/…`), que un
    // simple prefijo de ruta no reconoce.
    if let Some(m) = mounts_below(s, dev)?.into_iter().next() {
        bail!(
            "{} está montado en {}; desmóntalo antes de escribir en {}",
            m.device,
            m.target,
            dev.display()
        );
    }
    Ok(())
}

// ------------------------------------------------------------- captura

pub struct CaptureOptions<'a> {
    /// Partición (o dispositivo) con el Btrfs.
    pub fs_device: &'a Path,
    /// Disco con la tabla de particiones. `None`: el que contiene
    /// `fs_device` según `lsblk`.
    pub disk: Option<&'a Path>,
    pub dest_dir: &'a Path,
    pub name: &'a str,
    pub zstd_level: i32,
    pub hash: HashAlgo,
}

/// Archivos que produce una captura.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutFiles {
    pub table: PathBuf,
    pub dump: PathBuf,
    pub esp: PathBuf,
}

impl LayoutFiles {
    pub fn new(dest_dir: &Path, name: &str) -> Self {
        Self {
            table: dest_dir.join(format!("{name}.gpt")),
            dump: dest_dir.join(format!("{name}.sfdisk.txt")),
            esp: dest_dir.join(format!("{name}.esp.img.zst")),
        }
    }

    fn all(&self) -> [PathBuf; 4] {
        [
            self.table.clone(),
            self.dump.clone(),
            self.esp.clone(),
            super::partial_path(&self.esp),
        ]
    }
}

/// [`capture_with`] con zstd 3, BLAKE3 y el disco buscado con `lsblk`.
pub fn capture(
    s: &mut Session,
    fs_device: &Path,
    dest_dir: &Path,
    name: &str,
) -> Result<DiskLayout> {
    capture_with(
        s,
        &CaptureOptions {
            fs_device,
            disk: None,
            dest_dir,
            name,
            zstd_level: 3,
            hash: HashAlgo::default(),
        },
    )
}

/// Guarda UUID, tabla de particiones y ESP. Si algo falla, borra lo que
/// había escrito.
pub fn capture_with(s: &mut Session, opts: &CaptureOptions) -> Result<DiskLayout> {
    if opts.name.is_empty() || opts.name.contains('/') {
        bail!("nombre de copia no válido: {:?}", opts.name);
    }
    guard_path(opts.fs_device)?;
    let files = LayoutFiles::new(opts.dest_dir, opts.name);
    for p in files.all() {
        if p.symlink_metadata().is_ok() {
            bail!("{} ya existe; no se sobrescribe", p.display());
        }
    }
    std::fs::create_dir_all(opts.dest_dir)
        .with_context(|| format!("creando {}", opts.dest_dir.display()))?;

    let res = capture_into(s, opts, &files);
    if res.is_err() {
        for p in files.all() {
            let _ = std::fs::remove_file(p);
        }
    }
    res
}

fn capture_into(s: &mut Session, opts: &CaptureOptions, files: &LayoutFiles) -> Result<DiskLayout> {
    let mut layout = DiskLayout::default();

    let (fstype, uuid) = probe(s, opts.fs_device)?;
    if fstype.as_deref() != Some("btrfs") {
        bail!(
            "{} no contiene un Btrfs (blkid dice {})",
            opts.fs_device.display(),
            fstype.as_deref().unwrap_or("nada")
        );
    }
    layout.fs_uuid = uuid;

    let disk = match opts.disk {
        Some(d) => Some(d.to_path_buf()),
        None => parent_disk(s, opts.fs_device)?,
    };
    let Some(disk) = disk else {
        layout.notes.push(format!(
            "{} no está en una partición: no hay tabla de particiones ni ESP que guardar",
            opts.fs_device.display()
        ));
        return Ok(layout);
    };
    guard_path(&disk)?;

    let table = read_table(s, &disk)?;
    let dump = s.run(Cmd::new("sfdisk").arg("--dump").arg(&disk))?;
    std::fs::write(&files.dump, &dump)
        .with_context(|| format!("escribiendo {}", files.dump.display()))?;
    layout.partition_table_dump = Some(StreamRef {
        digest: Some(Digest::of_file(opts.hash, &files.dump)?),
        ..StreamRef::plain(files.dump.clone())
    });
    layout.notes.push(format!(
        "tabla de {} ({}, {} particiones); volcado legible en {} ({})",
        disk.display(),
        table.label,
        table.partitions.len(),
        files.dump.display(),
        Digest::of_file(opts.hash, &files.dump)?
    ));

    if table.label == "gpt" {
        let mut arg = std::ffi::OsString::from("--backup=");
        arg.push(&files.table);
        s.run(Cmd::new("sgdisk").arg(arg).arg(&disk))?;
        layout.partition_table = Some(StreamRef {
            digest: Some(Digest::of_file(opts.hash, &files.table)?),
            ..StreamRef::plain(files.table.clone())
        });
    } else {
        layout.notes.push(format!(
            "la tabla es {}, no GPT: solo se guarda el volcado de sfdisk (restaurar con `sfdisk <disco> < {}`)",
            table.label,
            files.dump.display()
        ));
    }

    match table.esp() {
        None => layout
            .notes
            .push(format!("no hay partición EFI en {}", disk.display())),
        Some((part, offset, len)) => {
            let digest = capture_esp(s, opts, &disk, offset, len, &files.esp)?;
            layout.notes.push(format!(
                "ESP: {} (uuid {}), {len} bytes desde el byte {offset}",
                part.node,
                part.uuid.as_deref().unwrap_or("?")
            ));
            layout.esp = Some(StreamRef {
                digest: Some(digest),
                ..StreamRef::plain(files.esp.clone())
            });
        }
    }
    Ok(layout)
}

fn dd_read(disk: &Path, offset: u64, len: u64) -> Cmd {
    let mut input = std::ffi::OsString::from("if=");
    input.push(disk);
    Cmd::new("dd")
        .arg(input)
        .arg("bs=1M")
        .arg("iflag=skip_bytes,count_bytes")
        .arg(format!("skip={offset}"))
        .arg(format!("count={len}"))
        .arg("status=none")
}

fn dd_write(disk: &Path, offset: u64, len: u64) -> Cmd {
    let mut output = std::ffi::OsString::from("of=");
    output.push(disk);
    Cmd::new("dd")
        .arg(output)
        .arg("bs=1M")
        .arg("iflag=fullblock,count_bytes")
        .arg(format!("count={len}"))
        .arg("oflag=seek_bytes")
        .arg(format!("seek={offset}"))
        .arg("conv=notrunc,fsync")
        .arg("status=none")
}

fn capture_esp(
    s: &mut Session,
    opts: &CaptureOptions,
    disk: &Path,
    offset: u64,
    len: u64,
    dest: &Path,
) -> Result<Digest> {
    // Que lo que el sistema tenga en caché de una ESP montada llegue al disco.
    s.run(Cmd::new("sync"))?;
    let partial = super::partial_path(dest);
    let file = File::options()
        .write(true)
        .create_new(true)
        .open(&partial)
        .with_context(|| format!("creando {}", partial.display()))?;
    let (raw, _, digest) = s.pipe_out(dd_read(disk, offset, len), |out| {
        compress_hashed(out, file, opts.zstd_level, opts.hash)
    })?;
    if raw != len {
        bail!(
            "la ESP de {} mide {len} bytes y solo se leyeron {raw}",
            disk.display()
        );
    }
    std::fs::rename(&partial, dest)
        .with_context(|| format!("renombrando {}", partial.display()))?;
    Ok(digest)
}

// --------------------------------------------------------- restauración

pub struct LayoutRestoreOptions<'a> {
    pub layout: &'a DiskLayout,
    /// Disco de destino: se reescriben su tabla y su ESP.
    pub target_disk: &'a Path,
    /// Btrfs ya restaurado y desmontado al que poner el UUID original.
    /// También se puede hacer después con [`apply_fs_uuid`].
    pub btrfs_device: Option<&'a Path>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LayoutRestored {
    pub partition_table: bool,
    /// (desplazamiento, bytes) de la ESP escrita.
    pub esp: Option<(u64, u64)>,
    pub fs_uuid: Option<String>,
    pub notes: Vec<String>,
}

/// Escribe la tabla de particiones y la ESP en `target_disk` y, si se
/// indica `btrfs_device`, pone el UUID original a ese Btrfs.
pub fn restore_layout(s: &mut Session, opts: &LayoutRestoreOptions) -> Result<LayoutRestored> {
    guard_path(opts.target_disk)?;
    if let Some(d) = opts.btrfs_device {
        guard_path(d)?;
        if opts.layout.fs_uuid.is_none() {
            bail!("la copia no tiene UUID del sistema de archivos que aplicar");
        }
    }
    // Nada se escribe si algún archivo está dañado.
    for r in [&opts.layout.partition_table, &opts.layout.esp]
        .into_iter()
        .flatten()
    {
        check_digest(r).context("no se ha escrito nada en el disco de destino")?;
    }
    let esp_raw = match &opts.layout.esp {
        None => None,
        Some(r) => Some(raw_size_and_digest(r)?),
    };
    ensure_unmounted(s, opts.target_disk)?;

    let mut done = LayoutRestored::default();
    match &opts.layout.partition_table {
        None => done
            .notes
            .push("la copia no tiene tabla GPT: no se ha tocado la tabla del destino".into()),
        Some(table) => {
            let mut arg = std::ffi::OsString::from("--load-backup=");
            arg.push(&table.path);
            s.run(Cmd::new("sgdisk").arg(arg).arg(opts.target_disk))?;
            let v = s.run(Cmd::new("sgdisk").arg("-v").arg(opts.target_disk))?;
            if !v.contains("No problems found") {
                bail!(
                    "la tabla restaurada en {} tiene problemas: {}",
                    opts.target_disk.display(),
                    v.trim()
                );
            }
            done.partition_table = true;
            // Que el kernel cree los nodos de las particiones nuevas. partx
            // lee la tabla él mismo, así que funciona aunque el kernel no
            // sepa leer GPT. Un fallo aquí no invalida lo escrito.
            let px = s.run_unchecked(&Cmd::new("partx").arg("-u").arg(opts.target_disk))?;
            if !px.success {
                done.notes.push(format!(
                    "`partx -u` falló ({}); el kernel puede no ver aún las particiones nuevas",
                    px.stderr.trim()
                ));
            }
        }
    }

    if let (Some(esp), Some((raw_len, raw_digest))) = (&opts.layout.esp, esp_raw) {
        let table = read_table(s, opts.target_disk)?;
        let (part, offset, len) = table.esp().ok_or_else(|| {
            anyhow!(
                "{} no tiene partición EFI donde escribir la ESP",
                opts.target_disk.display()
            )
        })?;
        if len != raw_len {
            bail!(
                "la ESP de destino ({}) mide {len} bytes y la imagen {raw_len}; no se escribe",
                part.node
            );
        }
        write_esp(s, esp, opts.target_disk, offset, len)?;
        let back = s.pipe_out(dd_read(opts.target_disk, offset, len), |r| {
            let mut h = Hasher::new(raw_digest.algo);
            io::copy(r, &mut h)?;
            Ok(h.finalize())
        })?;
        if back != raw_digest {
            bail!(
                "la ESP escrita en {} no coincide al releerla: {back}, se esperaba {raw_digest}",
                opts.target_disk.display()
            );
        }
        done.esp = Some((offset, len));
        done.notes.push(format!(
            "ESP escrita y releída en {} ({len} bytes)",
            part.node
        ));
    }

    if let Some(dev) = opts.btrfs_device {
        let uuid = opts.layout.fs_uuid.as_deref().expect("comprobado arriba");
        apply_fs_uuid(s, uuid, dev)?;
        done.fs_uuid = Some(uuid.to_string());
    }
    Ok(done)
}

/// Tamaño y hash del contenido descomprimido de una imagen.
fn raw_size_and_digest(r: &StreamRef) -> Result<(u64, Digest)> {
    let algo = r.digest.as_ref().map_or(HashAlgo::default(), |d| d.algo);
    let mut w = Counting {
        hasher: Hasher::new(algo),
        bytes: 0,
        cap: u64::MAX,
    };
    decompress_into(&r.path, algo, &mut w)?;
    Ok((w.bytes, w.hasher.finalize()))
}

fn write_esp(s: &mut Session, esp: &StreamRef, disk: &Path, offset: u64, len: u64) -> Result<()> {
    let algo = esp.digest.as_ref().map_or(HashAlgo::default(), |d| d.algo);
    let mut got = None;
    s.pipe_in(dd_write(disk, offset, len), |stdin| {
        let mut w = Counting {
            hasher: Hasher::new(algo),
            bytes: 0,
            cap: len,
        };
        let mut out = Tee {
            a: &mut w,
            b: stdin,
        };
        got = Some(decompress_into(&esp.path, algo, &mut out)?);
        Ok(())
    })?;
    if let (Some(want), Some(got)) = (&esp.digest, got) {
        if *want != got {
            bail!("{} cambió mientras se escribía", esp.path.display());
        }
    }
    Ok(())
}

/// Pone `uuid` al Btrfs (desmontado) de `dev` con `btrfstune -U` y lo comprueba.
pub fn apply_fs_uuid(s: &mut Session, uuid: &str, dev: &Path) -> Result<()> {
    guard_path(dev)?;
    ensure_unmounted(s, dev)?;
    let (fstype, current) = probe(s, dev)?;
    if fstype.as_deref() != Some("btrfs") {
        bail!("{} no contiene un Btrfs; no se le pone UUID", dev.display());
    }
    if current.as_deref() == Some(uuid) {
        return Ok(());
    }
    // btrfstune pregunta antes de cambiar el UUID.
    s.pipe_in(
        Cmd::new("btrfstune").arg("-U").arg(uuid).arg(dev),
        |stdin| {
            let _ = stdin.write_all(b"y\n");
            Ok(())
        },
    )
    .with_context(|| {
        format!(
            "poniendo el UUID {uuid} a {} (si dice que no es único, desconecta el disco original)",
            dev.display()
        )
    })?;
    let (_, now) = probe(s, dev)?;
    if now.as_deref() != Some(uuid) {
        bail!(
            "{} tiene el UUID {} tras btrfstune; se esperaba {uuid}",
            dev.display(),
            now.as_deref().unwrap_or("ninguno")
        );
    }
    Ok(())
}

/// Hashea y cuenta, y falla si se pasa de `cap` bytes.
struct Counting {
    hasher: Hasher,
    bytes: u64,
    cap: u64,
}

impl Write for Counting {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.bytes + buf.len() as u64 > self.cap {
            return Err(io::Error::other(format!(
                "la imagen supera los {} bytes de la partición",
                self.cap
            )));
        }
        self.hasher.update(buf);
        self.bytes += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Escribe en `a` (que puede rechazar) y luego en `b`.
struct Tee<'a, A, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
}

impl<A: Write, B: Write + ?Sized> Write for Tee<'_, A, B> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.a.write_all(buf)?;
        self.b.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.b.flush()
    }
}

#[cfg(test)]
mod tests;
