//! Proves a send stream restores: receive it into a scratch Btrfs on a loop
//! device, check the result and compare it with the source.
//!
//! A backup is only `Valid` when every step passed. A skipped step makes it
//! `Reduced`, which callers must not present as a success.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cmd::{Cmd, Session};
use crate::send::decompress_into;
use crate::types::{Digest, HashAlgo, Step, StepStatus, StreamRef, Verdict, Verification};
use anyhow::{bail, Context, Result};

pub mod compare;
use compare::compare_trees;

pub struct VerifyOptions<'a> {
    /// The chain to restore, in order: a full stream, then incrementals.
    pub streams: &'a [StreamRef],
    /// Tree the last restored subvolume must match (usually the snapshot
    /// that was sent). `None` skips the content step.
    pub reference: Option<&'a Path>,
    pub scratch_dir: &'a Path,
    /// Apparent size of the sparse scratch image.
    pub scratch_size: u64,
}

pub const STEPS: [&str; 5] = [
    "integridad",
    "restaurar",
    "subvolumen",
    "contenido",
    "estructura",
];

pub fn verify(s: &mut Session, opts: &VerifyOptions) -> Result<Verification> {
    if opts.streams.is_empty() {
        bail!("no hay ningún stream que verificar");
    }
    let mut steps: Vec<Step> = Vec::new();
    let mut comparison = None;
    let mut push = |name, status, detail: String| {
        steps.push(Step {
            name,
            status,
            detail,
        })
    };

    let mut scratch = Scratch::create(s, opts.scratch_dir, opts.scratch_size)?;

    // Restoring also hashes each compressed file, which feeds "integridad".
    let mut restored = Ok(PathBuf::new());
    let mut mismatches = Vec::new();
    let mut unhashed = 0;
    for stream in opts.streams {
        match scratch.receive(s, stream) {
            Ok((subvol, got)) => {
                match &stream.digest {
                    Some(want) if *want != got => mismatches.push(format!(
                        "{}: {got}, se esperaba {want}",
                        stream.path.display()
                    )),
                    Some(_) => {}
                    None => unhashed += 1,
                }
                restored = Ok(subvol);
            }
            Err(e) => {
                restored = Err(e.context(format!("restaurando {}", stream.path.display())));
                break;
            }
        }
    }
    let n = opts.streams.len();
    match &restored {
        Err(_) => push(
            "integridad",
            StepStatus::Failed,
            "algún stream no se pudo leer entero".into(),
        ),
        Ok(_) if !mismatches.is_empty() => {
            push("integridad", StepStatus::Failed, mismatches.join("; "))
        }
        Ok(_) if unhashed > 0 => push(
            "integridad",
            StepStatus::Skipped,
            format!("{unhashed} de {n} streams sin hash de referencia"),
        ),
        Ok(_) => push(
            "integridad",
            StepStatus::Passed,
            format!("hash correcto en {n} stream(s)"),
        ),
    }

    match restored {
        Err(e) => {
            push("restaurar", StepStatus::Failed, format!("{e:#}"));
            for name in &STEPS[2..] {
                push(
                    name,
                    StepStatus::Failed,
                    "no se ejecutó porque falló la restauración".into(),
                );
            }
        }
        Ok(subvol) => {
            push(
                "restaurar",
                StepStatus::Passed,
                format!("{n} stream(s) recibidos; último en {}", subvol.display()),
            );

            match check_received(s, &subvol) {
                Ok(d) => push("subvolumen", StepStatus::Passed, d),
                Err(e) => push("subvolumen", StepStatus::Failed, format!("{e:#}")),
            }

            match opts.reference {
                None => push(
                    "contenido",
                    StepStatus::Skipped,
                    "no se indicó con qué comparar".into(),
                ),
                Some(reference) => match compare_trees(reference, &subvol) {
                    Ok(c) => {
                        let detail = format!(
                            "{} entradas, {} archivos, {} bytes",
                            c.entries, c.files, c.bytes
                        );
                        if c.identical() {
                            push("contenido", StepStatus::Passed, detail);
                        } else {
                            push(
                                "contenido",
                                StepStatus::Failed,
                                format!("{} diferencias; {detail}", c.total_differences),
                            );
                        }
                        comparison = Some(c);
                    }
                    Err(e) => push("contenido", StepStatus::Failed, format!("{e:#}")),
                },
            }

            match scratch.check(s) {
                Ok(()) => push(
                    "estructura",
                    StepStatus::Passed,
                    "btrfs check --readonly sin errores".into(),
                ),
                Err(e) => push("estructura", StepStatus::Failed, format!("{e:#}")),
            }
        }
    }

    scratch.cleanup(s);

    let verdict = if steps.iter().any(|x| x.status == StepStatus::Failed) {
        Verdict::Invalid
    } else if steps.iter().any(|x| x.status == StepStatus::Skipped) {
        Verdict::Reduced
    } else {
        Verdict::Valid
    };
    Ok(Verification {
        verdict,
        steps,
        comparison,
    })
}

pub(crate) fn check_received(s: &mut Session, subvol: &Path) -> Result<String> {
    let show = s.run(Cmd::new("btrfs").arg("subvolume").arg("show").arg(subvol))?;
    let received = show
        .lines()
        .find_map(|l| l.trim().strip_prefix("Received UUID:"))
        .map(str::trim)
        .unwrap_or("-");
    if received == "-" {
        bail!("el subvolumen restaurado no tiene Received UUID");
    }
    let ro = s.run(
        Cmd::new("btrfs")
            .arg("property")
            .arg("get")
            .arg("-ts")
            .arg(subvol)
            .arg("ro"),
    )?;
    if ro.trim() != "ro=true" {
        bail!(
            "el subvolumen restaurado no es de solo lectura ({})",
            ro.trim()
        );
    }
    Ok(format!("solo lectura, Received UUID {received}"))
}

/// Receives one stream into `dir` and returns the new subvolume and the
/// digest of the compressed file (same algorithm as the expected one).
pub(crate) fn receive_into(
    s: &mut Session,
    stream: &StreamRef,
    dir: &Path,
) -> Result<(PathBuf, Digest)> {
    let algo = stream
        .digest
        .as_ref()
        .map_or(HashAlgo::default(), |d| d.algo);
    let before = entries(dir)?;
    let mut hash = None;
    s.pipe_in(Cmd::new("btrfs").arg("receive").arg(dir), |stdin| {
        hash = Some(decompress_into(&stream.path, algo, stdin)?);
        Ok(())
    })?;
    let hash = hash.expect("set when receive succeeds");
    let mut new: Vec<_> = entries(dir)?
        .into_iter()
        .filter(|p| !before.contains(p))
        .collect();
    match new.len() {
        1 => Ok((new.remove(0), hash)),
        n => bail!(
            "se esperaba un subvolumen nuevo en {} y hay {n}",
            dir.display()
        ),
    }
}

fn entries(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(dir).with_context(|| format!("leyendo {}", dir.display()))? {
        v.push(e?.path());
    }
    Ok(v)
}

/// Sparse image + loop device + mount, torn down on every path.
struct Scratch {
    image: PathBuf,
    loopdev: Option<String>,
    mountpoint: tempfile::TempDir,
    mounted: bool,
}

impl Scratch {
    fn create(s: &mut Session, dir: &Path, size: u64) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let image = dir.join(format!("partshield-verify-{}.img", std::process::id()));
        File::create(&image)
            .and_then(|f| f.set_len(size))
            .with_context(|| format!("creando la imagen temporal {}", image.display()))?;
        let mountpoint = tempfile::Builder::new()
            .prefix("partshield-mnt-")
            .tempdir()?;
        let mut me = Self {
            image,
            loopdev: None,
            mountpoint,
            mounted: false,
        };
        s.run(Cmd::new("mkfs.btrfs").arg("-q").arg(&me.image))?;
        let dev = s.run(
            Cmd::new("losetup")
                .arg("--find")
                .arg("--show")
                .arg(&me.image),
        )?;
        me.loopdev = Some(dev.trim().to_string());
        s.run(Cmd::new("mount").arg(dev.trim()).arg(me.mountpoint.path()))?;
        me.mounted = true;
        Ok(me)
    }

    /// Returns the received subvolume and the digest of the stream file.
    fn receive(&mut self, s: &mut Session, stream: &StreamRef) -> Result<(PathBuf, Digest)> {
        receive_into(s, stream, self.mountpoint.path())
    }

    fn check(&mut self, s: &mut Session) -> Result<()> {
        self.unmount(s)?;
        let dev = self.loopdev.clone().expect("loop device attached");
        s.run(Cmd::new("btrfs").arg("check").arg("--readonly").arg(dev))?;
        Ok(())
    }

    fn unmount(&mut self, s: &mut Session) -> Result<()> {
        if self.mounted {
            s.run(Cmd::new("umount").arg(self.mountpoint.path()))?;
            self.mounted = false;
        }
        Ok(())
    }

    fn cleanup(&mut self, s: &mut Session) {
        let _ = self.unmount(s);
        if let Some(dev) = self.loopdev.take() {
            let _ = s.run(Cmd::new("losetup").arg("--detach").arg(dev));
        }
        let _ = std::fs::remove_file(&self.image);
    }
}

impl Drop for Scratch {
    /// Fallback for early returns and panics; normal paths call `cleanup`.
    fn drop(&mut self) {
        if self.mounted {
            let _ = Command::new("umount").arg(self.mountpoint.path()).status();
        }
        if let Some(dev) = self.loopdev.take() {
            let _ = Command::new("losetup").arg("--detach").arg(dev).status();
        }
        let _ = std::fs::remove_file(&self.image);
    }
}
