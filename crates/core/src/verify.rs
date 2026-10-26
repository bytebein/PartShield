//! Proves a send stream restores: receive it into a scratch Btrfs on a loop
//! device, check the result and compare it with the source.
//!
//! A backup is only `Valid` when every step passed. A skipped step makes it
//! `Reduced`, which callers must not present as a success.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::cmd::{Cmd, Session};
use crate::compare::{compare_trees, Comparison};
use crate::send::decompress_into;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
pub struct Step {
    pub name: &'static str,
    pub status: StepStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Every step passed.
    Valid,
    /// Nothing failed, but some steps were skipped.
    Reduced,
    Invalid,
}

#[derive(Debug, Clone, Serialize)]
pub struct Verification {
    pub verdict: Verdict,
    pub steps: Vec<Step>,
    pub comparison: Option<Comparison>,
}

pub struct VerifyOptions<'a> {
    pub stream: &'a Path,
    pub expected_blake3: Option<&'a str>,
    /// Tree the restored subvolume must match (usually the snapshot that
    /// was sent). `None` skips the content step.
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

    // Restoring also hashes the compressed file, which feeds "integridad".
    let restored = scratch.receive(s, opts.stream);
    match (&restored, opts.expected_blake3) {
        (Ok((_, got)), Some(want)) if got == want => {
            push("integridad", StepStatus::Passed, format!("blake3 {got}"))
        }
        (Ok((_, got)), Some(want)) => push(
            "integridad",
            StepStatus::Failed,
            format!("blake3 {got}, se esperaba {want}"),
        ),
        (Ok(_), None) => push(
            "integridad",
            StepStatus::Skipped,
            "no hay hash de referencia".into(),
        ),
        (Err(_), _) => push(
            "integridad",
            StepStatus::Failed,
            "el stream no se pudo leer entero".into(),
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
        Ok((subvol, _)) => {
            push(
                "restaurar",
                StepStatus::Passed,
                format!("recibido en {}", subvol.display()),
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

fn check_received(s: &mut Session, subvol: &Path) -> Result<String> {
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

    /// Returns the received subvolume and the BLAKE3 of the stream file.
    fn receive(&mut self, s: &mut Session, stream: &Path) -> Result<(PathBuf, String)> {
        let mut hash = String::new();
        s.pipe_in(
            Cmd::new("btrfs").arg("receive").arg(self.mountpoint.path()),
            |stdin| {
                hash = decompress_into(stream, stdin)?;
                Ok(())
            },
        )?;
        let mut entries =
            std::fs::read_dir(self.mountpoint.path())?.collect::<Result<Vec<_>, _>>()?;
        match entries.len() {
            1 => Ok((entries.remove(0).path(), hash)),
            n => bail!("se esperaba un subvolumen recibido y hay {n} entradas"),
        }
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
