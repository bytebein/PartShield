//! `btrfs send` mode: read-only snapshot → zstd-compressed send stream.
//!
//! - [`send`]: un subvolumen, completo o incremental (`-p`).
//! - [`multi`]: varios subvolúmenes (`@`, `@home`…) en una misma copia.
//! - [`layout`]: lo que no está en ningún subvolumen (tabla de particiones,
//!   ESP, UUID del sistema de archivos).
//! - [`restore`]: la vuelta, comprobando cada hash antes de recibir.

use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::cmd::{Cmd, Session};
use crate::types::{
    Artifact, BackupMode, BackupRequest, Digest, HashAlgo, Hasher, Mode, StreamRef,
};
use anyhow::{anyhow, bail, Context, Result};

pub mod layout;
pub mod multi;
pub mod restore;

#[cfg(test)]
mod testutil;

/// `btrfs send` por subvolumen: el modo por defecto.
pub struct SendMode;

impl BackupMode for SendMode {
    fn mode(&self) -> Mode {
        Mode::Send
    }

    fn backup(&self, s: &mut Session, req: &BackupRequest) -> Result<Artifact> {
        send(
            s,
            &SendOptions {
                source: req.source,
                dest_dir: req.dest_dir,
                snapshot_dir: req.snapshot_dir,
                name: req.name,
                zstd_level: req.zstd_level,
                parent: req.parent,
                hash: req.hash,
            },
        )
    }

    fn restore(&self, s: &mut Session, chain: &[StreamRef], target: &Path) -> Result<PathBuf> {
        let r = restore::restore(
            s,
            &restore::RestoreOptions {
                streams: chain,
                target,
                writable_name: None,
            },
        )?;
        Ok(r.received)
    }
}

pub struct SendOptions<'a> {
    pub source: &'a Path,
    pub dest_dir: &'a Path,
    /// Where to create the read-only snapshot; must be on the same
    /// filesystem. Defaults to inside `source`.
    pub snapshot_dir: Option<&'a Path>,
    pub name: &'a str,
    pub zstd_level: i32,
    /// Snapshot of the previous backup; makes this one incremental.
    pub parent: Option<&'a Path>,
    pub hash: HashAlgo,
}

/// Rutas que produce una copia. Ninguna debe existir antes de empezar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPaths {
    pub snapshot: PathBuf,
    pub stream: PathBuf,
    /// El stream se escribe aquí y solo se renombra a `stream` si terminó
    /// bien, así un `.btrfs.zst` nunca es una copia a medias.
    pub partial: PathBuf,
}

impl SendPaths {
    pub fn for_options(opts: &SendOptions) -> Self {
        let snap_parent = opts.snapshot_dir.unwrap_or(opts.source);
        let stream = opts.dest_dir.join(format!("{}.btrfs.zst", opts.name));
        Self {
            snapshot: snap_parent.join(format!(".partshield-{}", opts.name)),
            partial: partial_path(&stream),
            stream,
        }
    }

    /// Falla si alguna ruta ya existe: una copia nunca pisa otra.
    pub fn ensure_free(&self) -> Result<()> {
        for p in [&self.stream, &self.partial, &self.snapshot] {
            if p.symlink_metadata().is_ok() {
                bail!("{} ya existe; no se sobrescribe", p.display());
            }
        }
        Ok(())
    }
}

fn partial_path(stream: &Path) -> PathBuf {
    let mut name = stream.file_name().unwrap_or_default().to_os_string();
    name.push(".partial");
    stream.with_file_name(name)
}

pub fn ensure_subvolume(s: &mut Session, path: &Path) -> Result<()> {
    s.run(Cmd::new("btrfs").arg("subvolume").arg("show").arg(path))
        .with_context(|| format!("{} no es un subvolumen Btrfs", path.display()))?;
    Ok(())
}

/// Block device (or image) backing the filesystem mounted at `path`.
pub fn backing_device(s: &mut Session, path: &Path) -> Result<PathBuf> {
    let out = s.run(
        Cmd::new("findmnt")
            .arg("-no")
            .arg("SOURCE")
            .arg("--target")
            .arg(path),
    )?;
    // Subvolume mounts print `/dev/sdX[/subvol]`.
    let dev = out.trim().split('[').next().unwrap_or_default();
    if dev.is_empty() {
        bail!("no se encontró el dispositivo de {}", path.display());
    }
    Ok(PathBuf::from(dev))
}

/// Identidad del sistema de archivos que contiene `path`: su UUID, o el
/// dispositivo montado si el UUID no se conoce.
pub fn filesystem_id(s: &mut Session, path: &Path) -> Result<String> {
    let out = s.run(
        Cmd::new("findmnt")
            .arg("-n")
            .arg("-P")
            .arg("-o")
            .arg("UUID,SOURCE")
            .arg("--target")
            .arg(path),
    )?;
    parse_fs_id(&out).ok_or_else(|| {
        anyhow!(
            "no se pudo saber en qué sistema de archivos está {}",
            path.display()
        )
    })
}

/// `UUID="…" SOURCE="/dev/x[/sub]"` → UUID, o el dispositivo sin el subvolumen.
fn parse_fs_id(findmnt_pairs: &str) -> Option<String> {
    let line = findmnt_pairs.lines().next()?;
    let get = |key: &str| {
        let start = line.find(&format!("{key}=\""))? + key.len() + 2;
        let len = line[start..].find('"')?;
        Some(line[start..start + len].to_string()).filter(|v| !v.is_empty())
    };
    get("UUID")
        .map(|u| format!("uuid:{u}"))
        .or_else(|| get("SOURCE").map(|d| format!("dev:{}", d.split('[').next().unwrap_or(&d))))
}

/// `btrfs property get -ts <subvol> ro` imprime `ro=true` o `ro=false`.
fn parse_ro(out: &str) -> Option<bool> {
    out.lines()
        .find_map(|l| l.trim().strip_prefix("ro="))
        .and_then(|v| match v.trim() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
}

pub fn is_read_only(s: &mut Session, subvol: &Path) -> Result<bool> {
    let out = s.run(
        Cmd::new("btrfs")
            .arg("property")
            .arg("get")
            .arg("-ts")
            .arg(subvol)
            .arg("ro"),
    )?;
    parse_ro(&out).ok_or_else(|| {
        anyhow!(
            "respuesta inesperada de `btrfs property get` para {}: {}",
            subvol.display(),
            out.trim()
        )
    })
}

/// Comprueba que `parent` sirve como padre de `btrfs send -p` para `source`,
/// con un mensaje que diga qué hacer en vez del error genérico de `btrfs`.
pub fn check_parent(s: &mut Session, source: &Path, parent: &Path) -> Result<()> {
    if !parent.exists() {
        bail!(
            "el snapshot padre {} no existe; la copia base debe conservar su snapshot",
            parent.display()
        );
    }
    s.run(Cmd::new("btrfs").arg("subvolume").arg("show").arg(parent))
        .with_context(|| {
            format!(
                "el padre {} no es un subvolumen Btrfs; una incremental necesita el snapshot de la copia anterior",
                parent.display()
            )
        })?;
    if !is_read_only(s, parent)? {
        bail!(
            "el padre {} no es de solo lectura; `btrfs send -p` solo acepta snapshots de solo \
             lectura (los que crea `btrfs subvolume snapshot -r`)",
            parent.display()
        );
    }
    let src_fs = filesystem_id(s, source)?;
    let parent_fs = filesystem_id(s, parent)?;
    if src_fs != parent_fs {
        bail!(
            "el padre {} está en otro sistema de archivos ({parent_fs}) que el origen {} ({src_fs}); \
             `btrfs send -p` solo funciona dentro del mismo Btrfs",
            parent.display(),
            source.display()
        );
    }
    Ok(())
}

/// Todo lo que se puede comprobar sin crear nada. Devuelve las rutas que
/// usará la copia.
pub fn preflight(s: &mut Session, opts: &SendOptions) -> Result<SendPaths> {
    if opts.name.is_empty() || opts.name.contains('/') {
        bail!("nombre de copia no válido: {:?}", opts.name);
    }
    ensure_subvolume(s, opts.source)?;
    let paths = SendPaths::for_options(opts);
    paths.ensure_free()?;
    if let Some(parent) = opts.parent {
        check_parent(s, opts.source, parent)?;
    }
    Ok(paths)
}

pub fn send(s: &mut Session, opts: &SendOptions) -> Result<Artifact> {
    let paths = preflight(s, opts)?;
    std::fs::create_dir_all(opts.dest_dir)
        .with_context(|| format!("creando {}", opts.dest_dir.display()))?;
    send_prepared(s, opts, paths)
}

/// Crea el snapshot y escribe el stream. En cualquier error borra el
/// archivo parcial y el snapshot, así que no deja nada a medias.
fn send_prepared(s: &mut Session, opts: &SendOptions, paths: SendPaths) -> Result<Artifact> {
    s.run(
        Cmd::new("btrfs")
            .arg("subvolume")
            .arg("snapshot")
            .arg("-r")
            .arg(opts.source)
            .arg(&paths.snapshot),
    )?;

    match write_stream(s, opts, &paths) {
        Ok((stream_bytes, compressed_bytes, digest)) => Ok(Artifact {
            stream: paths.stream,
            snapshot: paths.snapshot,
            digest,
            compressed_bytes,
            stream_bytes,
            encryption: None,
            chunks: None,
        }),
        Err(e) => {
            let _ = std::fs::remove_file(&paths.partial);
            let _ = std::fs::remove_file(&paths.stream);
            Err(match delete_subvolume(s, &paths.snapshot) {
                Ok(()) => e,
                Err(d) => e.context(format!(
                    "además no se pudo borrar el snapshot {}: {d:#}",
                    paths.snapshot.display()
                )),
            })
        }
    }
}

fn write_stream(
    s: &mut Session,
    opts: &SendOptions,
    paths: &SendPaths,
) -> Result<(u64, u64, Digest)> {
    let mut cmd = Cmd::new("btrfs").arg("send");
    if let Some(parent) = opts.parent {
        cmd = cmd.arg("-p").arg(parent);
    }
    let cmd = cmd.arg(&paths.snapshot);

    let file = File::options()
        .write(true)
        .create_new(true)
        .open(&paths.partial)
        .with_context(|| format!("creando {}", paths.partial.display()))?;
    let (stream_bytes, compressed_bytes, digest) = s.pipe_out(cmd, |out| {
        compress_hashed(out, file, opts.zstd_level, opts.hash)
    })?;
    std::fs::rename(&paths.partial, &paths.stream).with_context(|| {
        format!(
            "renombrando {} a {}",
            paths.partial.display(),
            paths.stream.display()
        )
    })?;
    Ok((stream_bytes, compressed_bytes, digest))
}

/// Comprime `input` con zstd en `file` y hashea los bytes comprimidos.
/// Devuelve (bytes leídos, bytes escritos, hash de lo escrito). Hace fsync.
pub(crate) fn compress_hashed(
    input: &mut dyn Read,
    file: File,
    level: i32,
    algo: HashAlgo,
) -> Result<(u64, u64, Digest)> {
    let hashing = HashingWriter::new(BufWriter::new(file), algo);
    let mut enc = zstd::Encoder::new(hashing, level)?;
    enc.multithread(num_threads())?;
    let raw_bytes = io::copy(input, &mut enc)?;
    let mut hashing = enc.finish()?;
    hashing.flush()?;
    let file = hashing
        .inner
        .into_inner()
        .map_err(|e| anyhow!("vaciando el búfer: {}", e.error()))?;
    file.sync_all()?;
    Ok((raw_bytes, hashing.bytes, hashing.hasher.finalize()))
}

pub fn delete_subvolume(s: &mut Session, path: &Path) -> Result<()> {
    s.run(Cmd::new("btrfs").arg("subvolume").arg("delete").arg(path))?;
    Ok(())
}

/// Decompresses a stream file into `w` and returns the digest of the
/// compressed bytes read.
pub fn decompress_into(stream: &Path, algo: HashAlgo, w: &mut dyn Write) -> Result<Digest> {
    // La ruta puede venir de un informe: con la sandbox, nunca un disco real.
    crate::cmd::guard_path(stream)?;
    let file = File::open(stream).with_context(|| format!("abriendo {}", stream.display()))?;
    let mut reader = HashingReader {
        inner: io::BufReader::new(file),
        hasher: Hasher::new(algo),
    };
    let mut dec = zstd::Decoder::with_buffer(&mut reader)?;
    io::copy(&mut dec, w).context("descomprimiendo el stream")?;
    drop(dec);
    // Hash whatever trailing bytes zstd did not need, so the digest covers the whole file.
    io::copy(&mut reader, &mut io::sink())?;
    Ok(reader.hasher.finalize())
}

/// Comprueba el hash de un archivo antes de usarlo.
pub(crate) fn check_digest(r: &StreamRef) -> Result<()> {
    if let Some(want) = &r.digest {
        let got = Digest::of_file(want.algo, &r.path)?;
        if got != *want {
            bail!(
                "{} está dañado: {got}, se esperaba {want}",
                r.path.display()
            );
        }
    }
    Ok(())
}

fn num_threads() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

pub(crate) struct HashingWriter<W> {
    pub(crate) inner: W,
    pub(crate) hasher: Hasher,
    pub(crate) bytes: u64,
}

impl<W> HashingWriter<W> {
    pub(crate) fn new(inner: W, algo: HashAlgo) -> Self {
        Self {
            inner,
            hasher: Hasher::new(algo),
            bytes: 0,
        }
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct HashingReader<R> {
    inner: R,
    hasher: Hasher,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

impl<R: io::BufRead> io::BufRead for HashingReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        if let Ok(buf) = self.inner.fill_buf() {
            self.hasher.update(&buf[..amt]);
        }
        self.inner.consume(amt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_roundtrip_hash_matches() {
        for algo in [HashAlgo::Blake3, HashAlgo::Sha256] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("x.zst");
            let data: Vec<u8> = (0..200_000u32).flat_map(|i| i.to_le_bytes()).collect();

            let (raw, written_bytes, written) =
                compress_hashed(&mut data.as_slice(), File::create(&path).unwrap(), 3, algo)
                    .unwrap();
            assert_eq!(raw, data.len() as u64);
            assert_eq!(written_bytes, std::fs::metadata(&path).unwrap().len());

            let mut out = Vec::new();
            let read = decompress_into(&path, algo, &mut out).unwrap();
            assert_eq!(out, data);
            assert_eq!(read, written);
            assert_eq!(read, Digest::of_file(algo, &path).unwrap());
        }
    }

    #[test]
    fn check_digest_spots_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x");
        std::fs::write(&path, b"hola").unwrap();
        let good = StreamRef {
            digest: Some(Digest::of_file(HashAlgo::Blake3, &path).unwrap()),
            ..StreamRef::plain(path.clone())
        };
        check_digest(&good).unwrap();
        std::fs::write(&path, b"hola!").unwrap();
        let err = check_digest(&good).unwrap_err().to_string();
        assert!(err.contains("dañado"), "{err}");
    }

    #[test]
    fn paths_and_partial_file() {
        let opts = SendOptions {
            source: Path::new("/mnt/raiz/@home"),
            dest_dir: Path::new("/copias"),
            snapshot_dir: None,
            name: "home-1",
            zstd_level: 3,
            parent: None,
            hash: HashAlgo::Blake3,
        };
        let p = SendPaths::for_options(&opts);
        assert_eq!(p.stream, Path::new("/copias/home-1.btrfs.zst"));
        assert_eq!(p.partial, Path::new("/copias/home-1.btrfs.zst.partial"));
        assert_eq!(p.snapshot, Path::new("/mnt/raiz/@home/.partshield-home-1"));
        let opts = SendOptions {
            snapshot_dir: Some(Path::new("/mnt/raiz/snaps")),
            ..opts
        };
        assert_eq!(
            SendPaths::for_options(&opts).snapshot,
            Path::new("/mnt/raiz/snaps/.partshield-home-1")
        );
    }

    #[test]
    fn ensure_free_refuses_leftovers() {
        let dir = tempfile::tempdir().unwrap();
        let p = SendPaths {
            snapshot: dir.path().join(".partshield-x"),
            stream: dir.path().join("x.btrfs.zst"),
            partial: dir.path().join("x.btrfs.zst.partial"),
        };
        p.ensure_free().unwrap();
        std::fs::write(&p.partial, "").unwrap();
        assert!(p.ensure_free().unwrap_err().to_string().contains("partial"));
    }

    #[test]
    fn parses_ro_property() {
        assert_eq!(parse_ro("ro=true\n"), Some(true));
        assert_eq!(parse_ro("ro=false\n"), Some(false));
        assert_eq!(parse_ro("ERROR: x\n"), None);
    }

    #[test]
    fn parses_filesystem_id() {
        assert_eq!(
            parse_fs_id("UUID=\"abc-1\" SOURCE=\"/dev/loop0[/@home]\"\n").as_deref(),
            Some("uuid:abc-1")
        );
        assert_eq!(
            parse_fs_id("UUID=\"\" SOURCE=\"/dev/loop0[/@home]\"\n").as_deref(),
            Some("dev:/dev/loop0")
        );
        assert_eq!(parse_fs_id(""), None);
    }

    /// Sin un Btrfs debajo, `send` falla antes de crear nada.
    #[test]
    fn send_on_non_subvolume_leaves_nothing() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let out = dest.path().join("salida");
        let mut s = Session::new(false);
        let err = send(
            &mut s,
            &SendOptions {
                source: src.path(),
                dest_dir: &out,
                snapshot_dir: None,
                name: "x",
                zstd_level: 3,
                parent: None,
                hash: HashAlgo::Blake3,
            },
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("no es un subvolumen"),
            "{err:#}"
        );
        assert!(!out.exists());
        assert_eq!(std::fs::read_dir(src.path()).unwrap().count(), 0);
    }

    #[test]
    fn rejects_bad_names() {
        let mut s = Session::new(false);
        for name in ["", "a/b"] {
            let err = preflight(
                &mut s,
                &SendOptions {
                    source: Path::new("/nada"),
                    dest_dir: Path::new("/nada"),
                    snapshot_dir: None,
                    name,
                    zstd_level: 3,
                    parent: None,
                    hash: HashAlgo::Blake3,
                },
            )
            .unwrap_err();
            assert!(err.to_string().contains("no válido"));
        }
        assert!(s.records.is_empty());
    }
}
