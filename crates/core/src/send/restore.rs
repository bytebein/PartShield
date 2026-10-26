//! Restores a backup chain onto a mounted Btrfs.
//!
//! Each stream's hash is checked before `btrfs receive` sees a byte of it,
//! so a corrupt file never gets half-applied to the destination.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use serde::Serialize;

use crate::cmd::{Cmd, Session};
use crate::types::{Digest, StreamRef};
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
        let dest = opts.target.join(name);
        if dest.exists() {
            bail!("{} ya existe; no se sobrescribe", dest.display());
        }
    }

    for stream in opts.streams {
        if let Some(want) = &stream.digest {
            let got = Digest::of_file(want.algo, &stream.path)?;
            if got != *want {
                bail!(
                    "{} está dañado: {got}, se esperaba {want}; no se ha restaurado nada de él",
                    stream.path.display()
                );
            }
        }
    }

    let mut last = PathBuf::new();
    for stream in opts.streams {
        last = receive_into(s, stream, opts.target)?.0;
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
