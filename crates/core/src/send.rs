//! `btrfs send` mode: read-only snapshot → zstd-compressed send stream.

use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::cmd::{Cmd, Session};

/// One file of a backup chain: a full stream followed by incrementals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamRef {
    pub path: PathBuf,
    /// BLAKE3 of the compressed file, when known.
    pub blake3: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Artifact {
    pub stream: PathBuf,
    pub snapshot: PathBuf,
    /// BLAKE3 of the compressed file, to detect later corruption.
    pub blake3: String,
    pub compressed_bytes: u64,
    pub stream_bytes: u64,
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

pub fn send(s: &mut Session, opts: &SendOptions) -> Result<Artifact> {
    ensure_subvolume(s, opts.source)?;
    std::fs::create_dir_all(opts.dest_dir)?;

    let snap_parent = opts.snapshot_dir.unwrap_or(opts.source);
    let snapshot = snap_parent.join(format!(".partshield-{}", opts.name));
    let stream = opts.dest_dir.join(format!("{}.btrfs.zst", opts.name));
    if stream.exists() {
        bail!("{} ya existe; no se sobrescribe", stream.display());
    }

    s.run(
        Cmd::new("btrfs")
            .arg("subvolume")
            .arg("snapshot")
            .arg("-r")
            .arg(opts.source)
            .arg(&snapshot),
    )?;

    let mut cmd = Cmd::new("btrfs").arg("send");
    if let Some(parent) = opts.parent {
        cmd = cmd.arg("-p").arg(parent);
    }
    let cmd = cmd.arg(&snapshot);

    let file = File::create(&stream).with_context(|| format!("creando {}", stream.display()))?;
    let result = s.pipe_out(cmd, |out| {
        let hashing = HashingWriter::new(BufWriter::new(file));
        let mut enc = zstd::Encoder::new(hashing, opts.zstd_level)?;
        enc.multithread(num_threads())?;
        let stream_bytes = io::copy(out, &mut enc)?;
        let mut hashing = enc.finish()?;
        hashing.flush()?;
        Ok((
            stream_bytes,
            hashing.bytes,
            hashing.hasher.finalize().to_hex().to_string(),
        ))
    });

    match result {
        Ok((stream_bytes, compressed_bytes, blake3)) => Ok(Artifact {
            stream,
            snapshot,
            blake3,
            compressed_bytes,
            stream_bytes,
        }),
        Err(e) => {
            let _ = std::fs::remove_file(&stream);
            let _ = delete_subvolume(s, &snapshot);
            Err(e)
        }
    }
}

pub fn delete_subvolume(s: &mut Session, path: &Path) -> Result<()> {
    s.run(Cmd::new("btrfs").arg("subvolume").arg("delete").arg(path))?;
    Ok(())
}

/// Decompresses a stream file into `w` and returns the BLAKE3 of the
/// compressed bytes read.
pub fn decompress_into(stream: &Path, w: &mut dyn Write) -> Result<String> {
    let file = File::open(stream).with_context(|| format!("abriendo {}", stream.display()))?;
    let mut reader = HashingReader {
        inner: io::BufReader::new(file),
        hasher: blake3::Hasher::new(),
    };
    let mut dec = zstd::Decoder::with_buffer(&mut reader)?;
    io::copy(&mut dec, w).context("descomprimiendo el stream")?;
    drop(dec);
    // Hash whatever trailing bytes zstd did not need, so the digest covers the whole file.
    io::copy(&mut reader, &mut io::sink())?;
    Ok(reader.hasher.finalize().to_hex().to_string())
}

/// BLAKE3 of a whole file.
pub fn hash_file(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("abriendo {}", path.display()))?;
    let mut h = blake3::Hasher::new();
    h.update_reader(file)?;
    Ok(h.finalize().to_hex().to_string())
}

fn num_threads() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

struct HashingWriter<W> {
    inner: W,
    hasher: blake3::Hasher,
    bytes: u64,
}

impl<W> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
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
    hasher: blake3::Hasher,
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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.zst");
        let data: Vec<u8> = (0..200_000u32).flat_map(|i| i.to_le_bytes()).collect();

        let hw = HashingWriter::new(File::create(&path).unwrap());
        let mut enc = zstd::Encoder::new(hw, 3).unwrap();
        enc.write_all(&data).unwrap();
        let hw = enc.finish().unwrap();
        let written_hash = hw.hasher.finalize().to_hex().to_string();

        let mut out = Vec::new();
        let read_hash = decompress_into(&path, &mut out).unwrap();
        assert_eq!(out, data);
        assert_eq!(read_hash, written_hash);
        assert_eq!(
            read_hash,
            blake3::hash(&std::fs::read(&path).unwrap())
                .to_hex()
                .to_string()
        );
    }
}
