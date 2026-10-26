//! `btrfs send` mode: read-only snapshot → zstd-compressed send stream.

use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::cmd::{Cmd, Session};
use crate::types::{
    Artifact, BackupMode, BackupRequest, Digest, HashAlgo, Hasher, Mode, StreamRef,
};
use anyhow::{bail, Context, Result};

pub mod restore;

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
        let hashing = HashingWriter::new(BufWriter::new(file), opts.hash);
        let mut enc = zstd::Encoder::new(hashing, opts.zstd_level)?;
        enc.multithread(num_threads())?;
        let stream_bytes = io::copy(out, &mut enc)?;
        let mut hashing = enc.finish()?;
        hashing.flush()?;
        Ok((stream_bytes, hashing.bytes, hashing.hasher.finalize()))
    });

    match result {
        Ok((stream_bytes, compressed_bytes, digest)) => Ok(Artifact {
            stream,
            snapshot,
            digest,
            compressed_bytes,
            stream_bytes,
            encryption: None,
            chunks: None,
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

/// Decompresses a stream file into `w` and returns the digest of the
/// compressed bytes read.
pub fn decompress_into(stream: &Path, algo: HashAlgo, w: &mut dyn Write) -> Result<Digest> {
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

fn num_threads() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

struct HashingWriter<W> {
    inner: W,
    hasher: Hasher,
    bytes: u64,
}

impl<W> HashingWriter<W> {
    fn new(inner: W, algo: HashAlgo) -> Self {
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

            let hw = HashingWriter::new(File::create(&path).unwrap(), algo);
            let mut enc = zstd::Encoder::new(hw, 3).unwrap();
            enc.write_all(&data).unwrap();
            let hw = enc.finish().unwrap();
            let written = hw.hasher.finalize();

            let mut out = Vec::new();
            let read = decompress_into(&path, algo, &mut out).unwrap();
            assert_eq!(out, data);
            assert_eq!(read, written);
            assert_eq!(read, Digest::of_file(algo, &path).unwrap());
        }
    }
}
