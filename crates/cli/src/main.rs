use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use partshield_core::cmd::Session;
use partshield_core::detect::{modes, SuperblockExt};
use partshield_core::raw;
use partshield_core::report::{load_prior, sign};
use partshield_core::send::restore::{restore, RestoreOptions};
use partshield_core::types::{
    ChecksumStatus, HashAlgo, StepStatus, StreamRef, Superblock, Verdict, Verification,
};
use partshield_core::verify::{self, VerifyOptions};
use partshield_core::{backup, backup_raw, partclone_version, BackupOptions, RawOptions};

/// Copias de Btrfs que no se dan por buenas hasta restaurarlas.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// No mostrar cada comando antes de ejecutarlo.
    #[arg(long, short, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Lee el superbloque y dice qué modos de copia son seguros.
    Inspect {
        /// Dispositivo o imagen con un Btrfs.
        device: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Copia y verifica restaurando: un subvolumen con btrfs send (por
    /// defecto) o un dispositivo entero sector a sector (--mode raw).
    Backup {
        /// Subvolumen montado (send) o dispositivo/imagen (raw).
        source: PathBuf,
        /// send: subvolumen con btrfs send. raw: todos los bytes, estilo dd;
        /// el origen no puede estar montado en lectura-escritura.
        #[arg(long, value_enum, default_value = "send")]
        mode: ModeArg,
        /// Carpeta donde se guardan el stream y el informe.
        #[arg(long)]
        dest: PathBuf,
        /// Dónde crear el snapshot de solo lectura (mismo sistema de archivos).
        #[arg(long)]
        snapshot_dir: Option<PathBuf>,
        /// Dónde crear la imagen temporal de verificación (por defecto, --dest).
        #[arg(long)]
        scratch_dir: Option<PathBuf>,
        /// Conservar el snapshot (base para copias incrementales).
        #[arg(long)]
        keep_snapshot: bool,
        /// Informe de una copia válida anterior: la nueva será incremental a ella.
        #[arg(long)]
        parent: Option<PathBuf>,
        #[arg(long, default_value_t = 3)]
        zstd_level: i32,
        /// Algoritmo de hash de los streams.
        #[arg(long, value_enum, default_value = "blake3")]
        hash: HashArg,
        /// Firmar el informe con esta clave ed25519 (se crea con permisos
        /// 0600 si no existe; la pública queda en <ruta>.pub).
        #[arg(long)]
        sign_key: Option<PathBuf>,
    },
    /// Comprueba la firma ed25519 de un informe.
    VerifyReport {
        report: PathBuf,
        /// Clave pública: archivo .pub o la clave en hex.
        #[arg(long)]
        public_key: String,
    },
    /// Verifica una copia restaurándola en un Btrfs temporal.
    Verify {
        /// Streams en orden (completo y luego incrementales), si no se da --report.
        streams: Vec<PathBuf>,
        /// Informe de la copia: toma de él la cadena y los hashes.
        #[arg(long, conflicts_with = "streams")]
        report: Option<PathBuf>,
        /// Árbol con el que debe coincidir lo restaurado.
        #[arg(long)]
        against: Option<PathBuf>,
        #[arg(long, default_value = "/var/tmp")]
        scratch_dir: PathBuf,
        /// Tamaño de la imagen temporal en GiB (es sparse).
        #[arg(long, default_value_t = 64)]
        scratch_gib: u64,
        /// Aceptar como correcta una verificación con pasos omitidos.
        #[arg(long)]
        accept_reduced: bool,
    },
    /// Restaura una copia en un Btrfs montado.
    Restore {
        /// Streams en orden (completo y luego incrementales), si no se da --report.
        streams: Vec<PathBuf>,
        /// Informe de la copia: toma de él la cadena y los hashes.
        #[arg(long, conflicts_with = "streams")]
        report: Option<PathBuf>,
        /// send: carpeta del Btrfs de destino. raw: dispositivo al menos igual
        /// de grande, o un archivo nuevo.
        #[arg(long)]
        to: PathBuf,
        /// Crear además un subvolumen escribible con este nombre (p. ej. home).
        #[arg(long = "as")]
        writable: Option<String>,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ModeArg {
    Send,
    Raw,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum HashArg {
    Blake3,
    Sha256,
}

impl From<HashArg> for HashAlgo {
    fn from(h: HashArg) -> Self {
        match h {
            HashArg::Blake3 => HashAlgo::Blake3,
            HashArg::Sha256 => HashAlgo::Sha256,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut s = Session::new(!cli.quiet);
    match run(cli.command, &mut s) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command, s: &mut Session) -> Result<ExitCode> {
    match command {
        Command::Inspect { device, json } => {
            let sb = Superblock::read_from(&device)?;
            let assessments = modes::assess(&sb.features, partclone_version(s));
            if json {
                let v = serde_json::json!({ "superblock": sb, "modes": assessments });
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                print_superblock(&sb);
                println!("\nModos de copia:");
                for a in &assessments {
                    let mark = if a.allowed { "sí" } else { "NO" };
                    println!("  {:<10} {mark}", format!("{:?}", a.mode).to_lowercase());
                    for r in &a.reasons {
                        println!("             - {r}");
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Backup {
            source,
            mode,
            dest,
            snapshot_dir,
            scratch_dir,
            keep_snapshot,
            parent,
            zstd_level,
            hash,
            sign_key,
        } => {
            if matches!(mode, ModeArg::Raw)
                && (parent.is_some() || keep_snapshot || snapshot_dir.is_some())
            {
                bail!("--parent, --keep-snapshot y --snapshot-dir solo valen con --mode send");
            }
            let (report, path) = match mode {
                ModeArg::Raw => backup_raw(
                    s,
                    &RawOptions {
                        device: &source,
                        dest_dir: &dest,
                        scratch_dir: scratch_dir.as_deref(),
                        zstd_level,
                        hash: hash.into(),
                        sign_key: sign_key.as_deref(),
                    },
                )?,
                ModeArg::Send => backup(
                    s,
                    &BackupOptions {
                        source: &source,
                        dest_dir: &dest,
                        snapshot_dir: snapshot_dir.as_deref(),
                        scratch_dir: scratch_dir.as_deref(),
                        keep_snapshot,
                        zstd_level,
                        parent_report: parent.as_deref(),
                        hash: hash.into(),
                        sign_key: sign_key.as_deref(),
                    },
                )?,
            };
            if let Some(a) = &report.artifact {
                println!(
                    "\nStream: {} ({} bytes, {})",
                    a.stream.display(),
                    a.compressed_bytes,
                    a.digest
                );
            }
            if let Some(v) = &report.verification {
                print_verification(v);
            }
            if let Some(e) = &report.error {
                println!("\nError: {e}");
            }
            println!("Informe: {}", path.display());
            println!("Informe HTML: {}", path.with_extension("html").display());
            if report.signature.is_some() {
                println!("Firmado con ed25519");
            }
            Ok(verdict_exit(report.verdict(), false))
        }
        Command::Verify {
            streams,
            report,
            against,
            scratch_dir,
            scratch_gib,
            accept_reduced,
        } => {
            if let Some((stream, image)) = report
                .as_deref()
                .map(raw::load_from_report)
                .transpose()?
                .flatten()
            {
                let v = raw::verify(s, &stream, &image, &scratch_dir)?;
                print_verification(&v);
                return Ok(verdict_exit(v.verdict, accept_reduced));
            }
            let (chain, snapshot) = chain(report, streams)?;
            // Without --against, compare with the backup's own snapshot if it was kept.
            let reference = against.or(snapshot.filter(|p| p.exists()));
            let v = verify::verify(
                s,
                &VerifyOptions {
                    streams: &chain,
                    reference: reference.as_deref(),
                    scratch_dir: &scratch_dir,
                    scratch_size: scratch_gib << 30,
                },
            )?;
            print_verification(&v);
            Ok(verdict_exit(v.verdict, accept_reduced))
        }
        Command::VerifyReport { report, public_key } => {
            let path = Path::new(&public_key);
            let pk = if path.exists() {
                sign::load_public_key(path)?
            } else {
                sign::parse_public_key(&public_key)?
            };
            partshield_core::report::verify_signature(&std::fs::read_to_string(&report)?, &pk)?;
            println!("Firma correcta: {}", report.display());
            Ok(ExitCode::SUCCESS)
        }
        Command::Restore {
            streams,
            report,
            to,
            writable,
        } => {
            if let Some((stream, image)) = report
                .as_deref()
                .map(raw::load_from_report)
                .transpose()?
                .flatten()
            {
                if writable.is_some() {
                    bail!("--as solo vale para copias en modo send");
                }
                let d = raw::restore_to(s, &stream, &image, &to)?;
                println!("\nRestaurada bit a bit en {} ({d})", to.display());
                return Ok(ExitCode::SUCCESS);
            }
            let (chain, _) = chain(report, streams)?;
            let r = restore(
                s,
                &RestoreOptions {
                    streams: &chain,
                    target: &to,
                    writable_name: writable.as_deref(),
                },
            )?;
            println!("\nRestaurado: {} ({})", r.received.display(), r.detail);
            if let Some(w) = &r.writable {
                println!("Subvolumen escribible: {}", w.display());
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// The streams to work on, from a report (plus its snapshot) or given in
/// order on the command line.
fn chain(
    report: Option<PathBuf>,
    streams: Vec<PathBuf>,
) -> Result<(Vec<StreamRef>, Option<PathBuf>)> {
    match report {
        Some(path) => {
            let prior = load_prior(&path)?;
            if !prior.valid {
                eprintln!(
                    "aviso: {} no es una copia válida; se usa igualmente",
                    path.display()
                );
            }
            Ok((prior.chain, Some(prior.snapshot)))
        }
        None if streams.is_empty() => bail!("indica los streams o --report"),
        None => Ok((streams.into_iter().map(StreamRef::plain).collect(), None)),
    }
}

fn print_superblock(sb: &Superblock) {
    println!("fsid:        {}", sb.fsid);
    println!("etiqueta:    {}", sb.label);
    println!(
        "tamaño:      {} bytes ({} usados)",
        sb.total_bytes, sb.bytes_used
    );
    println!("dispositivos:{:>2}", sb.num_devices);
    println!(
        "chunk_root:  {} (nivel {})",
        sb.chunk_root, sb.chunk_root_level
    );
    let csum = match sb.checksum {
        ChecksumStatus::Valid => "crc32c correcto".to_string(),
        ChecksumStatus::NotVerified { csum_type } => format!("tipo {csum_type}, no verificado"),
    };
    println!("checksum:    {csum}");
    println!("compat_ro:   {}", sb.features.compat_ro.names().join(", "));
    println!("incompat:    {}", sb.features.incompat.names().join(", "));
}

fn print_verification(v: &Verification) {
    println!("\nVerificación:");
    for st in &v.steps {
        let mark = match st.status {
            StepStatus::Passed => "ok  ",
            StepStatus::Failed => "FALLO",
            StepStatus::Skipped => "omit",
        };
        println!("  [{mark}] {:<11} {}", st.name, st.detail);
    }
    if let Some(c) = &v.comparison {
        for d in &c.differences {
            println!("         - {d}");
        }
    }
    let verdict = match v.verdict {
        Verdict::Valid => "COPIA VÁLIDA: restaurada y comprobada",
        Verdict::Reduced => "VERIFICACIÓN REDUCIDA: hay pasos omitidos",
        Verdict::Invalid => "COPIA NO VÁLIDA: no la uses como única copia",
    };
    println!("\n{verdict}");
}

fn verdict_exit(v: Verdict, accept_reduced: bool) -> ExitCode {
    match v {
        Verdict::Valid => ExitCode::SUCCESS,
        Verdict::Reduced if accept_reduced => ExitCode::SUCCESS,
        Verdict::Reduced => ExitCode::from(2),
        Verdict::Invalid => ExitCode::FAILURE,
    }
}
