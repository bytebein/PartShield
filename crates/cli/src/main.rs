use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use partshield_core::cmd::Session;
use partshield_core::modes;
use partshield_core::superblock::{ChecksumStatus, Superblock};
use partshield_core::verify::{self, StepStatus, Verdict, Verification, VerifyOptions};
use partshield_core::{backup, partclone_version, BackupOptions};

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
    /// Copia un subvolumen con btrfs send y verifica la copia restaurándola.
    Backup {
        /// Subvolumen montado que se copia.
        source: PathBuf,
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
        #[arg(long, default_value_t = 3)]
        zstd_level: i32,
    },
    /// Verifica un stream restaurándolo en un Btrfs temporal.
    Verify {
        stream: PathBuf,
        /// Árbol con el que debe coincidir lo restaurado.
        #[arg(long)]
        against: Option<PathBuf>,
        /// Hash BLAKE3 esperado del archivo comprimido.
        #[arg(long)]
        blake3: Option<String>,
        #[arg(long, default_value = "/var/tmp")]
        scratch_dir: PathBuf,
        /// Tamaño de la imagen temporal en GiB (es sparse).
        #[arg(long, default_value_t = 64)]
        scratch_gib: u64,
        /// Aceptar como correcta una verificación con pasos omitidos.
        #[arg(long)]
        accept_reduced: bool,
    },
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
            dest,
            snapshot_dir,
            scratch_dir,
            keep_snapshot,
            zstd_level,
        } => {
            let (report, path) = backup(
                s,
                &BackupOptions {
                    source: &source,
                    dest_dir: &dest,
                    snapshot_dir: snapshot_dir.as_deref(),
                    scratch_dir: scratch_dir.as_deref(),
                    keep_snapshot,
                    zstd_level,
                },
            )?;
            if let Some(a) = &report.artifact {
                println!(
                    "\nStream: {} ({} bytes, blake3 {})",
                    a.stream.display(),
                    a.compressed_bytes,
                    a.blake3
                );
            }
            if let Some(v) = &report.verification {
                print_verification(v);
            }
            if let Some(e) = &report.error {
                println!("\nError: {e}");
            }
            println!("Informe: {}", path.display());
            Ok(verdict_exit(report.verdict(), false))
        }
        Command::Verify {
            stream,
            against,
            blake3,
            scratch_dir,
            scratch_gib,
            accept_reduced,
        } => {
            let v = verify::verify(
                s,
                &VerifyOptions {
                    stream: &stream,
                    expected_blake3: blake3.as_deref(),
                    reference: against.as_deref(),
                    scratch_dir: &scratch_dir,
                    scratch_size: scratch_gib << 30,
                },
            )?;
            print_verification(&v);
            Ok(verdict_exit(v.verdict, accept_reduced))
        }
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
