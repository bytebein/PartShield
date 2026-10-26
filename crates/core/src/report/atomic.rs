//! Escritura atómica que nunca sobrescribe.
//!
//! El contenido se escribe en un temporal del mismo directorio (creado con
//! `O_EXCL`), se sincroniza a disco y se mueve a su nombre final con
//! `renameat2(RENAME_NOREPLACE)` (o `link` + `unlink` donde no exista, vía
//! `tempfile::persist_noclobber`). Un corte a mitad deja como mucho un
//! temporal `.<nombre>.*.tmp`, nunca un informe truncado con el nombre bueno,
//! y si el destino ya existe falla sin tocarlo.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// Escribe `data` en `path` de forma atómica, con permisos `mode`.
/// Falla si `path` ya existe.
pub fn write_new(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    if path.symlink_metadata().is_ok() {
        bail!(
            "{} ya existe; un informe nunca se sobrescribe",
            path.display()
        );
    }
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .with_context(|| format!("{} no es un nombre de archivo", path.display()))?;
    let mut tmp = tempfile::Builder::new()
        .prefix(&format!(".{}.", name.to_string_lossy()))
        .suffix(".tmp")
        .tempfile_in(dir)
        .with_context(|| format!("creando un temporal en {}", dir.display()))?;
    tmp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("ajustando permisos de {}", tmp.path().display()))?;
    tmp.write_all(data)
        .and_then(|()| tmp.as_file().sync_all())
        .with_context(|| format!("escribiendo {}", tmp.path().display()))?;
    tmp.persist_noclobber(path).map_err(|e| {
        if e.error.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!(
                "{} ya existe; un informe nunca se sobrescribe",
                path.display()
            )
        } else {
            anyhow::Error::new(e.error).context(format!("escribiendo {}", path.display()))
        }
    })?;
    // Que el nuevo nombre también sobreviva a un corte.
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.json");
        write_new(&p, b"uno", 0o644).unwrap();
        let err = write_new(&p, b"dos", 0o644).unwrap_err();
        assert!(format!("{err:#}").contains("ya existe"), "{err:#}");
        assert_eq!(std::fs::read(&p).unwrap(), b"uno");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o644
        );
        // Ningún temporal queda atrás.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn refuses_a_dangling_symlink_as_destination() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("enlace");
        std::os::unix::fs::symlink(dir.path().join("no-existe"), &p).unwrap();
        assert!(write_new(&p, b"x", 0o644).is_err());
        assert!(!dir.path().join("no-existe").exists());
    }
}
