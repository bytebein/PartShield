//! Modo raw: imagen sector a sector, al estilo de `dd`, comprimida con zstd.
//!
//! Copia todos los bytes del dispositivo, entienda o no su contenido. Es el
//! último recurso cuando ni `btrfs send` ni partclone sirven (features no
//! probadas, sistema de archivos dañado o desconocido). A cambio exige que
//! el origen no esté montado en lectura-escritura, porque una imagen de un
//! sistema de archivos que cambia mientras se lee no es coherente.
//!
//! La verificación es más fuerte que en send: además de restaurar, montar y
//! pasar `btrfs check`, exige que los bytes restaurados den exactamente el
//! mismo hash que los bytes leídos del dispositivo.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::cmd::{guard_path, Cmd, Session};
use crate::detect::blockdev::mounts_below;
use crate::detect::SuperblockExt;
use crate::types::{
    Artifact, Digest, HashAlgo, Hasher, RawImage, Step, StepStatus, StreamRef, Superblock,
    Verification,
};
use crate::verify::{verdict_of, COMPARACION, ESTRUCTURA, MONTAJE, MUESTRA, RESTAURAR};

/// Tamaño de lectura y de la unidad de escritura dispersa.
const BLOCK: usize = 4 << 20;

pub struct RawBackupOptions<'a> {
    /// Dispositivo (o archivo de imagen) a copiar entero.
    pub device: &'a Path,
    pub dest_dir: &'a Path,
    pub name: &'a str,
    pub zstd_level: i32,
    pub hash: HashAlgo,
}

/// Falla si `device`, o algo que cuelga de él (particiones, LUKS, LVM),
/// está montado en lectura-escritura: la imagen saldría incoherente.
pub fn ensure_not_mounted_rw(s: &mut Session, device: &Path) -> Result<()> {
    if let Some(m) = mounts_below(s, device)?.into_iter().find(|m| m.read_write) {
        bail!(
            "{} está montado en lectura-escritura en {}; desmóntalo o vuelve a montarlo \
             en solo lectura (mount -o remount,ro) antes de la imagen sector a sector",
            m.device,
            m.target
        );
    }
    Ok(())
}

/// Falla si `device` o algo que cuelga de él está montado, aunque sea en
/// solo lectura: escribir debajo de un sistema montado lo corrompe.
pub fn ensure_not_mounted(s: &mut Session, device: &Path) -> Result<()> {
    if let Some(m) = mounts_below(s, device)?.into_iter().next() {
        bail!(
            "{} está montado en {}; desmóntalo antes de restaurar sobre {}",
            m.device,
            m.target,
            device.display()
        );
    }
    Ok(())
}

/// Lee el dispositivo entero y escribe `<name>.raw.zst` en `dest_dir`.
pub fn backup(s: &mut Session, opts: &RawBackupOptions) -> Result<(Artifact, RawImage)> {
    guard_path(opts.device)?;
    ensure_not_mounted_rw(s, opts.device)?;
    std::fs::create_dir_all(opts.dest_dir)?;

    let mut src =
        File::open(opts.device).with_context(|| format!("abriendo {}", opts.device.display()))?;
    let size = src.seek(SeekFrom::End(0))?;
    src.seek(SeekFrom::Start(0))?;

    let stream = opts.dest_dir.join(format!("{}.raw.zst", opts.name));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stream)
        .with_context(|| format!("creando {} (no se sobrescribe)", stream.display()))?;

    let result = (|| -> Result<(Digest, Digest, u64)> {
        let tee = Tee::new(BufWriter::new(file), opts.hash);
        let mut enc = zstd::Encoder::new(tee, opts.zstd_level)?;
        enc.multithread(num_threads())?;
        let mut content = Hasher::new(opts.hash);
        let mut buf = vec![0u8; BLOCK];
        let mut done = 0u64;
        while done < size {
            let want = BLOCK.min((size - done) as usize);
            src.read_exact(&mut buf[..want]).with_context(|| {
                format!(
                    "error de lectura en {} cerca del byte {done}; si el disco está fallando, \
                     saca primero una imagen con ddrescue y copia esa imagen",
                    opts.device.display()
                )
            })?;
            content.update(&buf[..want]);
            enc.write_all(&buf[..want])?;
            done += want as u64;
        }
        let mut tee = enc.finish()?;
        tee.flush()?;
        tee.inner.get_ref().sync_all()?;
        Ok((tee.hasher.finalize(), content.finalize(), tee.bytes))
    })();

    match result {
        Ok((digest, content_digest, compressed_bytes)) => Ok((
            Artifact {
                stream,
                snapshot: opts.device.to_path_buf(),
                digest,
                compressed_bytes,
                stream_bytes: size,
                encryption: None,
                chunks: None,
            },
            RawImage {
                device: opts.device.to_path_buf(),
                size_bytes: size,
                content_digest,
            },
        )),
        Err(e) => {
            let _ = std::fs::remove_file(&stream);
            Err(e)
        }
    }
}

/// Restaura una imagen en `target`: un dispositivo de bloque al menos igual
/// de grande, o un archivo nuevo (que se escribe disperso).
///
/// Comprueba el hash del archivo comprimido antes de escribir nada y
/// devuelve el hash de los bytes restaurados, que debe coincidir con
/// `raw.content_digest` (la función falla si no).
pub fn restore_to(
    s: &mut Session,
    stream: &StreamRef,
    raw: &RawImage,
    target: &Path,
) -> Result<Digest> {
    guard_path(target)?;
    guard_path(&stream.path)?;
    if let Some(want) = &stream.digest {
        let got = Digest::of_file(want.algo, &stream.path)?;
        if got != *want {
            bail!(
                "{} está dañado: {got}, se esperaba {want}; no se ha escrito nada",
                stream.path.display()
            );
        }
    }

    let is_block = std::fs::metadata(target)
        .map(|m| m.file_type().is_block_device())
        .unwrap_or(false);
    let mut out = if is_block {
        ensure_not_mounted(s, target)?;
        let mut f = OpenOptions::new()
            .write(true)
            .open(target)
            .with_context(|| format!("abriendo {}", target.display()))?;
        let cap = f.seek(SeekFrom::End(0))?;
        if cap < raw.size_bytes {
            bail!(
                "{} tiene {cap} bytes y la imagen {}; el destino debe ser al menos igual de grande",
                target.display(),
                raw.size_bytes
            );
        }
        f.seek(SeekFrom::Start(0))?;
        f
    } else {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(target)
            .with_context(|| format!("creando {} (no se sobrescribe)", target.display()))?
    };
    let res = write_restored(&mut out, stream, raw, is_block);
    if res.is_err() && !is_block {
        // El archivo lo hemos creado nosotros: a medias no sirve y bloquearía
        // un reintento (no se sobrescribe nunca).
        drop(out);
        let _ = std::fs::remove_file(target);
    }
    res
}

fn write_restored(
    out: &mut File,
    stream: &StreamRef,
    raw: &RawImage,
    is_block: bool,
) -> Result<Digest> {
    let file =
        File::open(&stream.path).with_context(|| format!("abriendo {}", stream.path.display()))?;
    let mut dec = zstd::Decoder::new(file)?;
    let mut content = Hasher::new(raw.content_digest.algo);
    let mut buf = vec![0u8; BLOCK];
    let mut done = 0u64;
    loop {
        let n = read_full(&mut dec, &mut buf).context("descomprimiendo la imagen")?;
        if n == 0 {
            break;
        }
        content.update(&buf[..n]);
        // En un archivo, los bloques a cero se dejan como huecos; en un
        // dispositivo hay que escribirlos porque puede tener datos viejos.
        if !is_block && buf[..n].iter().all(|&b| b == 0) {
            out.seek(SeekFrom::Current(n as i64))?;
        } else {
            out.write_all(&buf[..n])?;
        }
        done += n as u64;
    }
    if done != raw.size_bytes {
        bail!(
            "la imagen tiene {done} bytes y el informe dice {}; está incompleta",
            raw.size_bytes
        );
    }
    if !is_block {
        out.set_len(done)?;
    }
    out.sync_all()?;

    let got = content.finalize();
    if got != raw.content_digest {
        bail!(
            "los bytes restaurados no son los originales: {got}, se esperaba {}",
            raw.content_digest
        );
    }
    Ok(got)
}

/// Restaura en una imagen temporal y pasa los cinco pasos. Nunca devuelve
/// `Valid` si alguno no pasó.
pub fn verify(
    s: &mut Session,
    stream: &StreamRef,
    raw: &RawImage,
    scratch_dir: &Path,
) -> Result<Verification> {
    std::fs::create_dir_all(scratch_dir)?;
    // Un directorio temporal propio: dos verificaciones a la vez en el mismo
    // directorio no se pisan la imagen.
    let dir = tempfile::Builder::new()
        .prefix("partshield-raw-verify-")
        .tempdir_in(scratch_dir)?;
    let mut scratch = Scratch {
        image: dir.path().join("restaurada.img"),
        _dir: dir,
        loopdev: None,
        mountpoint: tempfile::Builder::new()
            .prefix("partshield-mnt-")
            .tempdir()?,
        mounted: false,
    };
    let mut steps = Vec::new();
    let mut push = |name, status, detail: String| {
        steps.push(Step {
            name,
            status,
            detail,
        })
    };

    // 1. restaurar (incluye el hash del archivo comprimido) y 4. comparación
    //    (hash de los bytes restaurados contra los del dispositivo).
    let restored = restore_to(s, stream, raw, &scratch.image);
    let (restore_ok, comparison) = match &restored {
        Ok(d) => (
            (
                StepStatus::Passed,
                format!("{} bytes restaurados", raw.size_bytes),
            ),
            (
                StepStatus::Passed,
                format!("idéntica bit a bit al dispositivo: {d}"),
            ),
        ),
        Err(e) => {
            let msg = format!("{e:#}");
            let cmp = if msg.contains("no son los originales") {
                (StepStatus::Failed, msg.clone())
            } else {
                (
                    StepStatus::Failed,
                    "no se ejecutó porque falló la restauración".into(),
                )
            };
            ((StepStatus::Failed, msg), cmp)
        }
    };
    push(RESTAURAR, restore_ok.0, restore_ok.1);

    // 2. estructura y 3. montaje, solo con una imagen completa.
    if restored.is_ok() {
        let is_btrfs = Superblock::read_from(&scratch.image).is_ok();
        match scratch.attach(s) {
            Err(e) => {
                push(ESTRUCTURA, StepStatus::Failed, format!("{e:#}"));
                push(MONTAJE, StepStatus::Failed, format!("{e:#}"));
            }
            Ok(dev) => {
                if is_btrfs {
                    match s.run(Cmd::new("btrfs").arg("check").arg("--readonly").arg(&dev)) {
                        Ok(_) => push(
                            ESTRUCTURA,
                            StepStatus::Passed,
                            "btrfs check --readonly sin errores".into(),
                        ),
                        Err(e) => push(ESTRUCTURA, StepStatus::Failed, format!("{e:#}")),
                    }
                } else {
                    push(
                        ESTRUCTURA,
                        StepStatus::Skipped,
                        "no es Btrfs; no hay comprobador de estructura para este contenido".into(),
                    );
                }
                match mountable(s, &dev) {
                    Some(why_not) => push(MONTAJE, StepStatus::Skipped, why_not),
                    None => match scratch.mount_ro(s, &dev) {
                        Ok(()) => push(
                            MONTAJE,
                            StepStatus::Passed,
                            "montada en solo lectura".into(),
                        ),
                        Err(e) => push(MONTAJE, StepStatus::Failed, format!("{e:#}")),
                    },
                }
            }
        }
    } else {
        for name in [ESTRUCTURA, MONTAJE] {
            push(
                name,
                StepStatus::Failed,
                "no se ejecutó porque falló la restauración".into(),
            );
        }
    }

    push(COMPARACION, comparison.0, comparison.1);

    // 5. muestra: relee trozos del dispositivo original y los compara con la
    //    imagen restaurada (detecta un origen que cambió después de la copia).
    if restored.is_err() {
        push(
            "muestra",
            StepStatus::Failed,
            "no se ejecutó porque falló la restauración".into(),
        );
    } else {
        match sample_against_source(raw, &scratch.image) {
            Ok(Some(detail)) => push(MUESTRA, StepStatus::Passed, detail),
            Ok(None) => push(
                "muestra",
                StepStatus::Skipped,
                format!(
                    "{} ya no está disponible para releerlo",
                    raw.device.display()
                ),
            ),
            Err(e) => push(MUESTRA, StepStatus::Failed, format!("{e:#}")),
        }
    }

    scratch.cleanup(s);
    let verdict = verdict_of(&steps);
    Ok(Verification {
        verdict,
        steps,
        comparison: None,
    })
}

const SAMPLES: usize = 64;
const SAMPLE_BYTES: usize = 1 << 20;

/// Compara `SAMPLES` trozos de `SAMPLE_BYTES` en posiciones deterministas
/// (derivadas del hash del contenido). `Ok(None)` si el origen ya no existe.
fn sample_against_source(raw: &RawImage, restored: &Path) -> Result<Option<String>> {
    if guard_path(&raw.device).is_err() || !raw.device.exists() {
        return Ok(None);
    }
    let mut src = File::open(&raw.device)?;
    let mut img = File::open(restored)?;
    let seed = u64::from_str_radix(&raw.content_digest.hex[..16], 16).unwrap_or(1) | 1;
    let offsets = sample_offsets(seed, raw.size_bytes, SAMPLES, SAMPLE_BYTES as u64);
    let (mut a, mut b) = (vec![0u8; SAMPLE_BYTES], vec![0u8; SAMPLE_BYTES]);
    for &off in &offsets {
        let len = SAMPLE_BYTES.min((raw.size_bytes - off) as usize);
        src.seek(SeekFrom::Start(off))?;
        img.seek(SeekFrom::Start(off))?;
        src.read_exact(&mut a[..len])?;
        img.read_exact(&mut b[..len])?;
        if a[..len] != b[..len] {
            bail!(
                "el byte {off} del origen ya no coincide con la copia: el dispositivo ha cambiado \
                 desde la copia o la copia no es fiel"
            );
        }
    }
    Ok(Some(format!(
        "{} trozos de {} KiB releídos del origen e iguales (semilla {seed:#x})",
        offsets.len(),
        SAMPLE_BYTES >> 10
    )))
}

/// Posiciones alineadas y sin repetir; incluye siempre el principio, donde
/// están el superbloque y la tabla de particiones.
fn sample_offsets(mut seed: u64, size: u64, count: usize, chunk: u64) -> Vec<u64> {
    let slots = size.div_ceil(chunk).max(1);
    let mut out = vec![0u64];
    let mut tries = 0;
    while out.len() < count.min(slots as usize) && tries < count * 20 {
        // xorshift64: reproducible y sin dependencias.
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let off = (seed % slots) * chunk;
        if !out.contains(&off) {
            out.push(off);
        }
        tries += 1;
    }
    out.sort_unstable();
    out
}

/// Lee hasta llenar `buf` o llegar al final.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

fn num_threads() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

/// Escritor que cuenta y hashea lo que pasa por él.
struct Tee<W> {
    inner: W,
    hasher: Hasher,
    bytes: u64,
}

impl<W> Tee<W> {
    fn new(inner: W, algo: HashAlgo) -> Self {
        Self {
            inner,
            hasher: Hasher::new(algo),
            bytes: 0,
        }
    }
}

impl<W: Write> Write for Tee<W> {
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

/// Imagen temporal + loop de solo lectura + montaje, liberados siempre.
/// `None` si `dev` tiene un sistema de archivos que montar; si no, por qué
/// se omite el montaje (un disco entero con tabla de particiones, swap…).
/// Omitirlo deja la copia en «reducida», nunca en «válida».
fn mountable(s: &mut Session, dev: &str) -> Option<String> {
    let out = s
        .run_unchecked(&Cmd::new("blkid").arg("-p").arg("-o").arg("export").arg(dev))
        .ok()?;
    let (_, fstype) = crate::detect::blockdev::parse_blkid_export(&out.stdout);
    let pttype = out
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("PTTYPE="))
        .map(str::to_string);
    match (fstype.as_deref(), pttype) {
        (Some("swap" | "crypto_LUKS" | "LVM2_member" | "linux_raid_member"), _) => Some(format!(
            "contiene {}, que no se monta; la comparación bit a bit cubre el contenido",
            fstype.unwrap_or_default()
        )),
        (Some(_), _) => None,
        (None, Some(pt)) => Some(format!(
            "es un disco entero con tabla de particiones {pt}; no se monta cada \
             partición, la comparación bit a bit cubre el contenido"
        )),
        (None, None) => Some(
            "no tiene un sistema de archivos reconocible que montar; la comparación \
             bit a bit cubre el contenido"
                .into(),
        ),
    }
}

struct Scratch {
    image: PathBuf,
    /// Contiene `image`; se borra al soltar `Scratch`, después de la imagen.
    _dir: tempfile::TempDir,
    loopdev: Option<String>,
    mountpoint: tempfile::TempDir,
    mounted: bool,
}

impl Scratch {
    fn attach(&mut self, s: &mut Session) -> Result<String> {
        let dev = s.run(
            Cmd::new("losetup")
                .arg("--find")
                .arg("--show")
                .arg("--read-only")
                .arg(&self.image),
        )?;
        let dev = dev.trim().to_string();
        self.loopdev = Some(dev.clone());
        Ok(dev)
    }

    fn mount_ro(&mut self, s: &mut Session, dev: &str) -> Result<()> {
        s.run(
            Cmd::new("mount")
                .arg("-o")
                .arg("ro")
                .arg(dev)
                .arg(self.mountpoint.path()),
        )?;
        self.mounted = true;
        Ok(())
    }

    fn cleanup(&mut self, s: &mut Session) {
        if self.mounted
            && s.run(Cmd::new("umount").arg(self.mountpoint.path()))
                .is_ok()
        {
            self.mounted = false;
        }
        if let Some(dev) = self.loopdev.take() {
            let _ = s.run(Cmd::new("losetup").arg("--detach").arg(dev));
        }
        let _ = std::fs::remove_file(&self.image);
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        use std::process::Command;
        if self.mounted {
            let _ = Command::new("umount").arg(self.mountpoint.path()).status();
        }
        if let Some(dev) = self.loopdev.take() {
            let _ = Command::new("losetup").arg("--detach").arg(dev).status();
        }
        let _ = std::fs::remove_file(&self.image);
    }
}

/// Stream e imagen de un informe en modo raw; `None` si el informe es de
/// otro modo. Si el disco de copias se montó en otra ruta, busca el stream
/// junto al informe.
pub fn load_from_report(path: &Path) -> Result<Option<(StreamRef, RawImage)>> {
    #[derive(Deserialize)]
    struct Partial {
        mode: String,
        raw: Option<RawImage>,
        #[serde(default)]
        chain: Vec<StreamRef>,
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("leyendo {}", path.display()))?;
    let p: Partial = serde_json::from_str(&text)
        .with_context(|| format!("{} no es un informe válido", path.display()))?;
    if p.mode != "raw" {
        return Ok(None);
    }
    let raw = p
        .raw
        .with_context(|| format!("{} no tiene los datos de la imagen", path.display()))?;
    let mut stream = p
        .chain
        .into_iter()
        .next()
        .with_context(|| format!("{} no tiene stream", path.display()))?;
    if !stream.path.exists() {
        if let (Some(dir), Some(name)) = (path.parent(), stream.path.file_name()) {
            stream.path = dir.join(name);
        }
    }
    Ok(Some((stream, raw)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un "dispositivo" de prueba: archivo con datos, ceros y una cola
    /// que no es múltiplo del bloque.
    fn fake_device(dir: &Path) -> PathBuf {
        let path = dir.join("disco.img");
        let mut f = File::create(&path).unwrap();
        let noise: Vec<u8> = (0..3 * BLOCK as u32 + 12_345)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        f.write_all(&noise[..BLOCK]).unwrap();
        f.write_all(&vec![0u8; 2 * BLOCK]).unwrap();
        f.write_all(&noise[BLOCK..]).unwrap();
        path
    }

    fn backup_of(dir: &Path, algo: HashAlgo) -> (Artifact, RawImage) {
        let dev = fake_device(dir);
        backup(
            &mut Session::new(false),
            &RawBackupOptions {
                device: &dev,
                dest_dir: &dir.join("copias"),
                name: "disco",
                zstd_level: 3,
                hash: algo,
            },
        )
        .unwrap()
    }

    #[test]
    fn roundtrip_is_bit_exact_and_sparse() {
        for algo in [HashAlgo::Blake3, HashAlgo::Sha256] {
            let dir = tempfile::tempdir().unwrap();
            let (artifact, raw) = backup_of(dir.path(), algo);
            assert_eq!(
                raw.size_bytes,
                std::fs::metadata(&raw.device).unwrap().len()
            );
            assert_eq!(
                raw.content_digest,
                Digest::of_file(algo, &raw.device).unwrap()
            );

            let target = dir.path().join("restaurado.img");
            let got = restore_to(
                &mut Session::new(false),
                &artifact.stream_ref(),
                &raw,
                &target,
            )
            .unwrap();
            assert_eq!(got, raw.content_digest);
            assert_eq!(
                std::fs::read(&target).unwrap(),
                std::fs::read(&raw.device).unwrap()
            );

            use std::os::unix::fs::MetadataExt;
            let used = std::fs::metadata(&target).unwrap().blocks() * 512;
            assert!(
                used < raw.size_bytes - BLOCK as u64,
                "los ceros deben quedar como huecos"
            );
        }
    }

    #[test]
    fn damaged_stream_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (artifact, raw) = backup_of(dir.path(), HashAlgo::Blake3);
        let mut bytes = std::fs::read(&artifact.stream).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        std::fs::write(&artifact.stream, bytes).unwrap();
        let target = dir.path().join("restaurado.img");
        let err = restore_to(
            &mut Session::new(false),
            &artifact.stream_ref(),
            &raw,
            &target,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("dañado"));
        assert!(!target.exists());
    }

    #[test]
    fn wrong_content_digest_is_caught_even_without_stream_hash() {
        let dir = tempfile::tempdir().unwrap();
        let (artifact, mut raw) = backup_of(dir.path(), HashAlgo::Blake3);
        raw.content_digest.hex = "00".repeat(32);
        let err = restore_to(
            &mut Session::new(false),
            &StreamRef::plain(artifact.stream.clone()),
            &raw,
            &dir.path().join("r.img"),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("no son los originales"));
    }

    #[test]
    fn never_overwrites_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let (artifact, raw) = backup_of(dir.path(), HashAlgo::Blake3);
        let target = dir.path().join("ocupado.img");
        std::fs::write(&target, "mío").unwrap();
        assert!(restore_to(
            &mut Session::new(false),
            &artifact.stream_ref(),
            &raw,
            &target
        )
        .is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"m\xc3\xado");
    }

    #[test]
    fn sample_offsets_are_deterministic_aligned_and_cover_start() {
        let a = sample_offsets(42, 100 << 20, 64, 1 << 20);
        assert_eq!(a, sample_offsets(42, 100 << 20, 64, 1 << 20));
        assert_eq!(a[0], 0);
        assert!(a.iter().all(|o| o % (1 << 20) == 0 && *o < 100 << 20));
        assert_eq!(sample_offsets(7, 3 << 20, 64, 1 << 20).len(), 3);
    }
}
