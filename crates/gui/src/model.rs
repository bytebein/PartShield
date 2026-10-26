//! Lo que la interfaz pide al motor, sin GTK: se puede probar sin pantalla.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use partshield_core::cmd::{CommandRecord, Session};
use partshield_core::detect::devices::{self, Disk};
use partshield_core::detect::modes::{assess_with_kernel, KernelFeatures};
use partshield_core::detect::superblock::SuperblockCopies;
use partshield_core::detect::{block_stack, read_all_copies};
use partshield_core::partclone_version;
use partshield_core::types::{Assessment, BlockStack, Superblock};

pub fn list_disks() -> Result<(Vec<Disk>, Vec<CommandRecord>)> {
    let mut s = Session::new(false);
    let disks = devices::list(&mut s)?;
    Ok((disks, s.records))
}

/// Todo lo que se sabe de un Btrfs sin escribir nada.
pub struct DetectInfo {
    pub device: PathBuf,
    pub copies: SuperblockCopies,
    pub superblock: Superblock,
    pub modes: Vec<Assessment>,
    pub stack: Result<BlockStack, String>,
    pub warnings: Vec<String>,
    pub commands: Vec<CommandRecord>,
}

pub fn detect(device: &Path) -> Result<DetectInfo> {
    let mut s = Session::new(false);
    let copies = read_all_copies(device).map_err(|e| {
        let hint = if e.to_string().contains("Permission denied") {
            " (hace falta ejecutar PartShield como root)"
        } else {
            ""
        };
        anyhow!("{e}{hint}")
    })?;
    let superblock = copies
        .primary()
        .cloned()
        .ok_or_else(|| anyhow!("el superbloque principal de {} no es válido", device.display()))?;
    let modes = assess_with_kernel(
        &superblock.features,
        partclone_version(&mut s),
        KernelFeatures::from_sysfs().as_ref(),
    );
    let stack = block_stack(&mut s, device).map_err(|e| format!("{e:#}"));
    let warnings = copies.discrepancies();
    Ok(DetectInfo {
        device: device.to_path_buf(),
        copies,
        superblock,
        modes,
        stack,
        warnings,
        commands: s.records,
    })
}
