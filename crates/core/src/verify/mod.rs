//! Proves a backup restores: receive its chain into a scratch Btrfs on a
//! loop device and check the result in five steps ([`STEPS`]):
//!
//! 1. `restaurar`: `btrfs receive` of every stream into a sparse image on a
//!    loop device, checking the hash of each stream file on the way.
//! 2. `estructura`: `btrfs check --readonly` on the unmounted loop device.
//! 3. `montaje`: mount it with `-o ro`; the restored subvolume must be
//!    read-only and have a Received UUID.
//! 4. `comparacion`: the whole metadata tree against the reference (types,
//!    sizes, permissions, owners, hard links, symlinks, xattrs), and
//!    `btrfs scrub start -B -R -r` on the read-only mount with no errors.
//! 5. `muestra`: BLAKE3 of the contents of a reproducible sample of files
//!    (or of all of them) against the reference; see [`sample`].
//!
//! A backup is only `Valid` when all five passed ([`verdict_of`]). A skipped
//! step (no stream hash, no reference) makes it `Reduced`, which callers
//! must not present as a success; any failure makes it `Invalid`.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cmd::{Cmd, Session};
use crate::send::decompress_into;
use crate::types::{
    Comparison, Digest, HashAlgo, Step, StepStatus, StreamRef, Verdict, Verification,
};
use anyhow::{bail, Context, Result};

pub mod compare;
pub mod sample;
mod xattr;

#[cfg(test)]
mod e2e;

use compare::{absorb, compare_content, compare_metadata, MetadataComparison};
pub use sample::ContentSample;

pub struct VerifyOptions<'a> {
    /// The chain to restore, in order: a full stream, then incrementals.
    pub streams: &'a [StreamRef],
    /// Tree the last restored subvolume must match (usually the snapshot
    /// that was sent). `None` skips the comparison and sample steps.
    pub reference: Option<&'a Path>,
    pub scratch_dir: &'a Path,
    /// Apparent size of the sparse scratch image.
    pub scratch_size: u64,
}

pub const RESTAURAR: &str = "restaurar";
pub const ESTRUCTURA: &str = "estructura";
pub const MONTAJE: &str = "montaje";
pub const COMPARACION: &str = "comparacion";
pub const MUESTRA: &str = "muestra";

/// Every step a `Valid` verification must have passed, in execution order.
pub const STEPS: [&str; 5] = [RESTAURAR, ESTRUCTURA, MONTAJE, COMPARACION, MUESTRA];

/// The verdict for a list of steps. `Valid` only when each of [`STEPS`]
/// appears exactly once and passed; any failure, missing, repeated or
/// unknown step is `Invalid`; otherwise (something skipped) `Reduced`.
pub fn verdict_of(steps: &[Step]) -> Verdict {
    let well_formed = steps.len() == STEPS.len()
        && STEPS
            .iter()
            .all(|n| steps.iter().filter(|s| s.name == *n).count() == 1);
    if !well_formed || steps.iter().any(|s| s.status == StepStatus::Failed) {
        Verdict::Invalid
    } else if steps.iter().any(|s| s.status != StepStatus::Passed) {
        Verdict::Reduced
    } else {
        Verdict::Valid
    }
}

/// [`verify_with`] with the default content sample.
pub fn verify(s: &mut Session, opts: &VerifyOptions) -> Result<Verification> {
    verify_with(s, opts, ContentSample::default())
}

pub fn verify_with(
    s: &mut Session,
    opts: &VerifyOptions,
    sample: ContentSample,
) -> Result<Verification> {
    run(s, opts, sample, &mut |_| Ok(()))
}

struct Steps(Vec<Step>);

impl Steps {
    fn push(&mut self, name: &'static str, status: StepStatus, detail: impl Into<String>) {
        self.0.push(Step {
            name,
            status,
            detail: detail.into(),
        });
    }

    fn not_run(&mut self, names: &[&'static str], why: &str) {
        for name in names {
            self.push(name, StepStatus::Failed, format!("no se ejecutó: {why}"));
        }
    }
}

/// `before_mount` sees the scratch image between `estructura` and
/// `montaje`; tests use it to damage the restored filesystem.
fn run(
    s: &mut Session,
    opts: &VerifyOptions,
    sample: ContentSample,
    before_mount: &mut dyn FnMut(&Path) -> Result<()>,
) -> Result<Verification> {
    if opts.streams.is_empty() {
        bail!("no hay ningún stream que verificar");
    }
    let mut scratch = Scratch::create(s, opts.scratch_dir, opts.scratch_size)?;
    let mut steps = Steps(Vec::new());
    let comparison = check(s, opts, sample, &mut scratch, &mut steps, before_mount);
    scratch.cleanup(s);
    let comparison = comparison?;

    let steps = steps.0;
    Ok(Verification {
        verdict: verdict_of(&steps),
        steps,
        comparison,
    })
}

fn check(
    s: &mut Session,
    opts: &VerifyOptions,
    sample: ContentSample,
    scratch: &mut Scratch,
    steps: &mut Steps,
    before_mount: &mut dyn FnMut(&Path) -> Result<()>,
) -> Result<Option<Comparison>> {
    // 1. restaurar
    let n = opts.streams.len();
    let mut mismatches = Vec::new();
    let mut unhashed = 0;
    let mut seed_digest = None;
    let mut subvol = PathBuf::new();
    for stream in opts.streams {
        match scratch.receive(s, stream) {
            Ok((received, got)) => {
                match &stream.digest {
                    Some(want) if *want != got => mismatches.push(format!(
                        "{} está dañado: {got}, se esperaba {want}",
                        stream.path.display()
                    )),
                    Some(_) => {}
                    None => unhashed += 1,
                }
                seed_digest.get_or_insert(got);
                subvol = received;
            }
            Err(e) => {
                steps.push(
                    RESTAURAR,
                    StepStatus::Failed,
                    format!("restaurando {}: {e:#}", stream.path.display()),
                );
                steps.not_run(&STEPS[1..], "falló la restauración");
                return Ok(None);
            }
        }
    }
    let name = subvol
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !mismatches.is_empty() {
        steps.push(RESTAURAR, StepStatus::Failed, mismatches.join("; "));
    } else if unhashed > 0 {
        steps.push(
            RESTAURAR,
            StepStatus::Skipped,
            format!(
                "{n} stream(s) recibidos en {name}, pero {unhashed} sin hash de referencia: \
                 su integridad no se comprobó"
            ),
        );
    } else {
        steps.push(
            RESTAURAR,
            StepStatus::Passed,
            format!("{n} stream(s) recibidos en {name}, todos con el hash esperado"),
        );
    }

    // 2. estructura
    match scratch.check(s) {
        Ok(()) => steps.push(
            ESTRUCTURA,
            StepStatus::Passed,
            "btrfs check --readonly sin errores",
        ),
        Err(e) => steps.push(ESTRUCTURA, StepStatus::Failed, format!("{e:#}")),
    }

    before_mount(&scratch.image)?;

    // 3. montaje
    if let Err(e) = scratch.mount(s, true) {
        steps.push(MONTAJE, StepStatus::Failed, format!("{e:#}"));
        steps.not_run(&STEPS[3..], "no se pudo montar en solo lectura");
        return Ok(None);
    }
    match check_received(s, &subvol) {
        Ok(d) => steps.push(
            MONTAJE,
            StepStatus::Passed,
            format!("montado con -o ro; {d}"),
        ),
        Err(e) => steps.push(MONTAJE, StepStatus::Failed, format!("{e:#}")),
    }

    // 4. comparacion
    let scrub = scratch.scrub(s);
    let metadata = opts.reference.map(|r| compare_metadata(r, &subvol));
    let mut parts = Vec::new();
    let mut failed = false;
    match &scrub {
        Ok(d) => parts.push(d.clone()),
        Err(e) => {
            failed = true;
            parts.push(format!("{e:#}"));
        }
    }
    match &metadata {
        None => parts.push("comparación omitida: no se indicó con qué comparar".into()),
        Some(Err(e)) => {
            failed = true;
            parts.push(format!("comparando metadatos: {e:#}"));
        }
        Some(Ok(m)) => {
            let c = &m.comparison;
            let summary = format!(
                "metadatos de {} entradas ({} archivos, {} bytes)",
                c.entries, c.files, c.bytes
            );
            if c.identical() {
                parts.push(format!("{summary} idénticos"));
            } else {
                failed = true;
                parts.push(format!(
                    "{} diferencias en los {summary}: {}",
                    c.total_differences,
                    c.differences.join("; ")
                ));
            }
        }
    }
    let status = if failed {
        StepStatus::Failed
    } else if metadata.is_none() {
        StepStatus::Skipped
    } else {
        StepStatus::Passed
    };
    steps.push(COMPARACION, status, parts.join("; "));

    // 5. muestra
    let (
        reference,
        MetadataComparison {
            mut comparison,
            files,
        },
    ) = match (opts.reference, metadata) {
        (None, _) => {
            steps.push(
                MUESTRA,
                StepStatus::Skipped,
                "no se indicó con qué comparar",
            );
            return Ok(None);
        }
        (Some(r), Some(Ok(m))) => (r, m),
        (Some(_), _) => {
            steps.push(
                MUESTRA,
                StepStatus::Failed,
                "no se ejecutó: no se pudo leer la lista de archivos de la referencia",
            );
            return Ok(None);
        }
    };
    let digest = seed_digest.expect("at least one stream was received");
    let seed = sample::seed_from(&digest);
    let chosen = sample::select(&files, seed, sample);
    let content = compare_content(reference, &subvol, &chosen);
    let how = match sample {
        ContentSample::All => "todos los archivos".to_string(),
        ContentSample::Sample => format!(
            "muestra con semilla {seed:#018x} (primeros 64 bits de {digest} de {}; \
             mínimo {} archivos o {} %, y {} MiB)",
            opts.streams[0].path.display(),
            sample::MIN_FILES,
            sample::MIN_FILE_PERCENT,
            sample::MIN_BYTES >> 20
        ),
    };
    let summary = format!(
        "BLAKE3 de {} de {} archivos ({} de {} bytes); {how}",
        content.files, comparison.files, content.bytes, comparison.bytes
    );
    if content.identical() {
        steps.push(MUESTRA, StepStatus::Passed, format!("{summary}: idénticos"));
    } else {
        steps.push(
            MUESTRA,
            StepStatus::Failed,
            format!(
                "{} diferencias: {}; {summary}",
                content.total_differences,
                content.differences.join("; ")
            ),
        );
    }
    absorb(&mut comparison, &content);
    Ok(Some(comparison))
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

/// Error counters of `btrfs scrub start -R`; any of them above zero fails.
const SCRUB_ERRORS: [&str; 8] = [
    "read_errors",
    "csum_errors",
    "verify_errors",
    "super_errors",
    "malloc_errors",
    "uncorrectable_errors",
    "unverified_errors",
    "corrected_errors",
];

/// Checks the output of `btrfs scrub start -B -R`: it must have finished
/// and every error counter must be present and zero.
fn parse_scrub(out: &str) -> Result<String> {
    let status = out
        .lines()
        .find_map(|l| l.trim().strip_prefix("Status:"))
        .map(str::trim);
    if status != Some("finished") {
        bail!(
            "el scrub no terminó (estado {})",
            status.unwrap_or("desconocido")
        );
    }
    let value = |key: &str| {
        out.lines().find_map(|l| {
            l.trim()
                .strip_prefix(key)?
                .strip_prefix(':')?
                .trim()
                .parse::<u64>()
                .ok()
        })
    };
    let mut bad = Vec::new();
    for key in SCRUB_ERRORS {
        match value(key) {
            Some(0) => {}
            Some(v) => bad.push(format!("{key}: {v}")),
            None => bail!("la salida del scrub no tiene {key}"),
        }
    }
    if !bad.is_empty() {
        bail!("el scrub encontró errores: {}", bad.join(", "));
    }
    let data = value("data_bytes_scrubbed").unwrap_or(0);
    let tree = value("tree_bytes_scrubbed").unwrap_or(0);
    Ok(format!(
        "scrub sin errores ({data} bytes de datos y {tree} de metadatos)"
    ))
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
        // A unique name, so concurrent verifications never share an image.
        let image = tempfile::Builder::new()
            .prefix("partshield-verify-")
            .suffix(".img")
            .tempfile_in(dir)
            .with_context(|| format!("creando la imagen temporal en {}", dir.display()))?
            .into_temp_path()
            .keep()?;
        let mut me = Self {
            image,
            loopdev: None,
            mountpoint: tempfile::Builder::new()
                .prefix("partshield-mnt-")
                .tempdir()?,
            mounted: false,
        };
        File::options()
            .write(true)
            .open(&me.image)
            .and_then(|f| f.set_len(size))
            .with_context(|| format!("dimensionando {}", me.image.display()))?;
        s.run(Cmd::new("mkfs.btrfs").arg("-q").arg(&me.image))?;
        let dev = s.run(
            Cmd::new("losetup")
                .arg("--find")
                .arg("--show")
                .arg(&me.image),
        )?;
        me.loopdev = Some(dev.trim().to_string());
        me.mount(s, false)?;
        Ok(me)
    }

    fn dev(&self) -> &str {
        self.loopdev.as_deref().expect("loop device attached")
    }

    fn mount(&mut self, s: &mut Session, read_only: bool) -> Result<()> {
        // Con compresión: si no, unos datos muy compresibles en el origen
        // pueden no caber restaurados (bug_compresible_grande_desborda_scratch).
        let opts = if read_only {
            "ro,compress=zstd"
        } else {
            "compress=zstd"
        };
        let cmd = Cmd::new("mount").arg("-o").arg(opts);
        s.run(cmd.arg(self.dev()).arg(self.mountpoint.path()))?;
        self.mounted = true;
        Ok(())
    }

    /// Returns the received subvolume and the digest of the stream file.
    fn receive(&mut self, s: &mut Session, stream: &StreamRef) -> Result<(PathBuf, Digest)> {
        receive_into(s, stream, self.mountpoint.path())
    }

    fn check(&mut self, s: &mut Session) -> Result<()> {
        self.unmount(s)?;
        let dev = self.dev().to_string();
        s.run(Cmd::new("btrfs").arg("check").arg("--readonly").arg(dev))?;
        Ok(())
    }

    /// Read-only scrub (`-r`): a normal scrub is refused on a read-only mount.
    fn scrub(&mut self, s: &mut Session) -> Result<String> {
        let out = s.run_unchecked(
            &Cmd::new("btrfs")
                .arg("scrub")
                .arg("start")
                .arg("-B")
                .arg("-R")
                .arg("-r")
                .arg(self.mountpoint.path()),
        )?;
        let parsed = parse_scrub(&out.stdout);
        match (parsed, out.success) {
            (Ok(d), true) => Ok(d),
            (Err(e), _) => Err(e.context(out.stderr.trim().to_string())),
            (Ok(_), false) => bail!(
                "btrfs scrub falló (código {:?}): {}",
                out.code,
                out.stderr.trim()
            ),
        }
    }

    fn unmount(&mut self, s: &mut Session) -> Result<()> {
        if self.mounted {
            s.run(Cmd::new("umount").arg(self.mountpoint.path()))?;
            self.mounted = false;
        }
        Ok(())
    }

    fn cleanup(&mut self, s: &mut Session) {
        if self.unmount(s).is_err() {
            // Busy: detach it now; the kernel finishes when it is released.
            let _ = s.run(Cmd::new("umount").arg("--lazy").arg(self.mountpoint.path()));
            self.mounted = false;
        }
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
            let ok = Command::new("umount")
                .arg(self.mountpoint.path())
                .status()
                .is_ok_and(|st| st.success());
            if !ok {
                let _ = Command::new("umount")
                    .arg("--lazy")
                    .arg(self.mountpoint.path())
                    .status();
            }
        }
        if let Some(dev) = self.loopdev.take() {
            let _ = Command::new("losetup").arg("--detach").arg(dev).status();
        }
        let _ = std::fs::remove_file(&self.image);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [StepStatus; 3] = [StepStatus::Passed, StepStatus::Skipped, StepStatus::Failed];

    fn steps(statuses: &[StepStatus]) -> Vec<Step> {
        STEPS
            .iter()
            .zip(statuses)
            .map(|(name, status)| Step {
                name,
                status: *status,
                detail: String::new(),
            })
            .collect()
    }

    /// Every combination of statuses for the five steps (3⁵ = 243).
    #[test]
    fn verdict_for_every_combination() {
        let mut seen = [0; 3];
        for code in 0..3usize.pow(5) {
            let statuses: Vec<_> = (0..5).map(|i| ALL[code / 3usize.pow(i) % 3]).collect();
            let got = verdict_of(&steps(&statuses));
            let want = if statuses.contains(&StepStatus::Failed) {
                Verdict::Invalid
            } else if statuses.contains(&StepStatus::Skipped) {
                Verdict::Reduced
            } else {
                Verdict::Valid
            };
            assert_eq!(got, want, "{statuses:?}");
            if got == Verdict::Valid {
                assert!(statuses.iter().all(|s| *s == StepStatus::Passed));
            }
            seen[got as usize] += 1;
        }
        // Exactly one combination is valid; 2⁵ − 1 are reduced.
        assert_eq!(seen, [1, 31, 211]);
    }

    #[test]
    fn missing_reference_is_reduced_never_valid() {
        use StepStatus::*;
        let v = verdict_of(&steps(&[Passed, Passed, Passed, Skipped, Skipped]));
        assert_eq!(v, Verdict::Reduced);
        let v = verdict_of(&steps(&[Passed, Passed, Passed, Skipped, Passed]));
        assert_eq!(v, Verdict::Reduced);
        let v = verdict_of(&steps(&[Passed, Passed, Passed, Failed, Skipped]));
        assert_eq!(v, Verdict::Invalid, "a failed scrub still fails");
    }

    #[test]
    fn incomplete_or_malformed_lists_are_invalid() {
        let passed = steps(&[StepStatus::Passed; 5]);
        assert_eq!(verdict_of(&passed), Verdict::Valid);
        assert_eq!(verdict_of(&[]), Verdict::Invalid);
        for i in 0..5 {
            let mut fewer = passed.clone();
            fewer.remove(i);
            assert_eq!(verdict_of(&fewer), Verdict::Invalid, "sin {}", STEPS[i]);

            let mut twice = passed.clone();
            twice.push(passed[i].clone());
            assert_eq!(
                verdict_of(&twice),
                Verdict::Invalid,
                "{} dos veces",
                STEPS[i]
            );

            let mut renamed = passed.clone();
            renamed[i].name = "otro";
            assert_eq!(verdict_of(&renamed), Verdict::Invalid);
        }
        let mut reordered = passed.clone();
        reordered.reverse();
        assert_eq!(
            verdict_of(&reordered),
            Verdict::Valid,
            "order does not matter"
        );
    }

    const SCRUB_OK: &str = "Scrub started:    Mon Oct 26 12:48:20 2026
Status:           finished
Duration:         0:00:00
\tdata_extents_scrubbed: 8
\ttree_extents_scrubbed: 22
\tdata_bytes_scrubbed: 524288
\ttree_bytes_scrubbed: 360448
\tread_errors: 0
\tcsum_errors: 0
\tverify_errors: 0
\tno_csum: 0
\tcsum_discards: 0
\tsuper_errors: 0
\tmalloc_errors: 0
\tuncorrectable_errors: 0
\tunverified_errors: 0
\tcorrected_errors: 0
\tlast_physical: 92798976
";

    #[test]
    fn scrub_output() {
        assert_eq!(
            parse_scrub(SCRUB_OK).unwrap(),
            "scrub sin errores (524288 bytes de datos y 360448 de metadatos)"
        );
        let bad = SCRUB_OK
            .replace("csum_errors: 0", "csum_errors: 1")
            .replace("uncorrectable_errors: 0", "uncorrectable_errors: 1");
        let e = parse_scrub(&bad).unwrap_err().to_string();
        assert_eq!(
            e,
            "el scrub encontró errores: csum_errors: 1, uncorrectable_errors: 1"
        );
        let aborted = SCRUB_OK.replace("finished", "aborted");
        assert!(parse_scrub(&aborted).is_err());
        let missing = SCRUB_OK.replace("\tsuper_errors: 0\n", "");
        assert!(parse_scrub(&missing).is_err());
        assert!(parse_scrub("").is_err());
    }
}
