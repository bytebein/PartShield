//! Restores a backup chain onto a mounted Btrfs.
//!
//! Each stream's hash is checked before `btrfs receive` sees a byte of it,
//! so a corrupt file never gets half-applied to the destination. If a
//! receive fails anyway, the subvolumes this call created are deleted.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use super::check_digest;
use crate::cmd::{Cmd, Session};
use crate::types::StreamRef;
use crate::verify::{check_received, receive_into};

#[derive(Debug, Clone, Serialize)]
pub struct Restored {
    /// Read-only subvolume received from the last stream.
    pub received: PathBuf,
    /// Writable snapshot of it, when one was requested.
    pub writable: Option<PathBuf>,
    pub detail: String,
}

pub struct RestoreOptions<'a> {
    pub streams: &'a [StreamRef],
    /// Directory on the destination Btrfs.
    pub target: &'a Path,
    /// Name for a writable snapshot of the result (e.g. `home`).
    pub writable_name: Option<&'a str>,
}

pub fn restore(s: &mut Session, opts: &RestoreOptions) -> Result<Restored> {
    if opts.streams.is_empty() {
        bail!("no hay ningún stream que restaurar");
    }
    if let Some(name) = opts.writable_name {
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            bail!("nombre no válido para el subvolumen escribible: {name:?}");
        }
        let dest = opts.target.join(name);
        if dest.symlink_metadata().is_ok() {
            bail!("{} ya existe; no se sobrescribe", dest.display());
        }
    }

    for stream in opts.streams {
        check_digest(stream).context("no se ha restaurado nada")?;
    }

    let before = entries(opts.target)?;
    let result = receive_chain(s, opts);
    if result.is_err() {
        // Lo que `btrfs receive` dejó a medias (o recibió entero de una
        // cadena que luego falló) no es una restauración válida.
        if let Ok(now) = entries(opts.target) {
            for p in now.into_iter().filter(|p| !before.contains(p)).rev() {
                let _ = s.run(Cmd::new("btrfs").arg("subvolume").arg("delete").arg(&p));
            }
        }
    }
    result
}

fn receive_chain(s: &mut Session, opts: &RestoreOptions) -> Result<Restored> {
    let mut last = PathBuf::new();
    for stream in opts.streams {
        last = receive_into(s, stream, opts.target)
            .with_context(|| format!("recibiendo {}", stream.path.display()))?
            .0;
    }
    let detail = check_received(s, &last)?;

    let writable = match opts.writable_name {
        None => None,
        Some(name) => {
            let dest = opts.target.join(name);
            s.run(
                Cmd::new("btrfs")
                    .arg("subvolume")
                    .arg("snapshot")
                    .arg(&last)
                    .arg(&dest),
            )?;
            Some(dest)
        }
    };

    Ok(Restored {
        received: last,
        writable,
        detail,
    })
}

fn entries(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(dir).with_context(|| format!("leyendo {}", dir.display()))? {
        v.push(e?.path());
    }
    v.sort();
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Digest, HashAlgo};

    #[test]
    fn corrupt_stream_runs_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.btrfs.zst");
        std::fs::write(&path, b"uno").unwrap();
        let r = StreamRef {
            digest: Some(Digest::of_file(HashAlgo::Sha256, &path).unwrap()),
            ..StreamRef::plain(path.clone())
        };
        std::fs::write(&path, b"dos").unwrap();
        let mut s = Session::new(false);
        let err = restore(
            &mut s,
            &RestoreOptions {
                streams: &[r],
                target: dir.path(),
                writable_name: None,
            },
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("dañado"));
        assert!(s.records.is_empty());
    }

    #[test]
    fn refuses_bad_or_taken_writable_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("home")).unwrap();
        let r = StreamRef::plain(dir.path().join("x"));
        let mut s = Session::new(false);
        for name in ["home", "a/b", ".."] {
            assert!(restore(
                &mut s,
                &RestoreOptions {
                    streams: std::slice::from_ref(&r),
                    target: dir.path(),
                    writable_name: Some(name),
                },
            )
            .is_err());
        }
        assert!(s.records.is_empty());
    }
}
