//! Varios subvolúmenes en una misma copia (p. ej. `@` y `@home`).
//!
//! `btrfs send` no cruza los límites de subvolumen: el snapshot de `@` deja
//! `@home` como un directorio vacío. Por eso cada subvolumen da su propio
//! [`Artifact`], identificado por una etiqueta. En una incremental, cada
//! subvolumen usa como padre el snapshot de la copia anterior con su misma
//! etiqueta, y su `chain` es la cadena anterior más el stream nuevo.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, Context, Result};

use super::restore::{restore, RestoreOptions, Restored};
use super::{check_digest, delete_subvolume, preflight, send_prepared, SendOptions};
use crate::cmd::Session;
use crate::types::HashAlgo;

/// Un subvolumen a copiar.
#[derive(Debug, Clone, Copy)]
pub struct SubvolSpec<'a> {
    /// Nombre estable entre copias (`@`, `@home`…): enlaza cada subvolumen
    /// con su copia anterior.
    pub label: &'a str,
    pub source: &'a Path,
}

pub use crate::types::SubvolArtifact;

pub struct MultiSendOptions<'a> {
    pub subvolumes: &'a [SubvolSpec<'a>],
    pub dest_dir: &'a Path,
    /// Dónde crear los snapshots; por defecto, dentro de cada subvolumen.
    pub snapshot_dir: Option<&'a Path>,
    /// Nombre de la copia; cada subvolumen añade `--<etiqueta>`.
    pub name: &'a str,
    pub zstd_level: i32,
    pub hash: HashAlgo,
    /// Copia anterior (con sus snapshots conservados). Cada subvolumen con
    /// una etiqueta que aparezca aquí se copia en incremental sobre ella.
    pub previous: &'a [SubvolArtifact],
}

/// Etiqueta → trozo de nombre de archivo. Solo letras, cifras y `@._-`.
pub fn label_slug(label: &str) -> Result<String> {
    if label.is_empty() || label == "." || label == ".." {
        bail!("etiqueta de subvolumen no válida: {label:?}");
    }
    Ok(label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "@._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect())
}

/// Nombre de la copia de un subvolumen: `<name>--<etiqueta>`.
pub fn subvol_name(name: &str, label: &str) -> Result<String> {
    Ok(format!("{name}--{}", label_slug(label)?))
}

fn plan_names(name: &str, subvolumes: &[SubvolSpec]) -> Result<Vec<String>> {
    if subvolumes.is_empty() {
        bail!("no hay ningún subvolumen que copiar");
    }
    let mut seen = HashSet::new();
    let mut names = Vec::new();
    for sv in subvolumes {
        let n = subvol_name(name, sv.label)?;
        if !seen.insert(n.clone()) {
            bail!(
                "dos subvolúmenes darían el mismo nombre de copia ({n}); usa etiquetas distintas"
            );
        }
        names.push(n);
    }
    Ok(names)
}

fn previous_for<'p>(previous: &'p [SubvolArtifact], label: &str) -> Option<&'p SubvolArtifact> {
    previous.iter().find(|p| p.label == label)
}

/// Copia cada subvolumen. Comprueba todos antes de crear nada y, si uno
/// falla a mitad, borra los streams y snapshots que ya se habían hecho:
/// o se copian todos o ninguno.
pub fn send_many(s: &mut Session, opts: &MultiSendOptions) -> Result<Vec<SubvolArtifact>> {
    let names = plan_names(opts.name, opts.subvolumes)?;

    let mut planned = Vec::new();
    for (sv, name) in opts.subvolumes.iter().zip(&names) {
        let prev = previous_for(opts.previous, sv.label);
        let send_opts = SendOptions {
            source: sv.source,
            dest_dir: opts.dest_dir,
            snapshot_dir: opts.snapshot_dir,
            name,
            zstd_level: opts.zstd_level,
            parent: prev.map(|p| p.artifact.snapshot.as_path()),
            hash: opts.hash,
        };
        let paths = preflight(s, &send_opts)
            .with_context(|| format!("subvolumen {} ({})", sv.label, sv.source.display()))?;
        planned.push((sv, prev, send_opts, paths));
    }
    std::fs::create_dir_all(opts.dest_dir)
        .with_context(|| format!("creando {}", opts.dest_dir.display()))?;

    let mut done: Vec<SubvolArtifact> = Vec::new();
    for (sv, prev, send_opts, paths) in planned {
        match send_prepared(s, &send_opts, paths) {
            Ok(artifact) => {
                let mut chain = prev.map(|p| p.chain.clone()).unwrap_or_default();
                chain.push(artifact.stream_ref());
                done.push(SubvolArtifact {
                    label: sv.label.to_string(),
                    source: sv.source.to_path_buf(),
                    parent: send_opts.parent.map(Path::to_path_buf),
                    artifact,
                    chain,
                });
            }
            Err(e) => {
                let e = e.context(format!("subvolumen {} ({})", sv.label, sv.source.display()));
                return Err(rollback(s, done, e));
            }
        }
    }
    Ok(done)
}

fn rollback(s: &mut Session, done: Vec<SubvolArtifact>, mut err: anyhow::Error) -> anyhow::Error {
    for d in done.into_iter().rev() {
        let _ = std::fs::remove_file(&d.artifact.stream);
        if let Err(e) = delete_subvolume(s, &d.artifact.snapshot) {
            err = err.context(format!(
                "además no se pudo borrar el snapshot {}: {e:#}",
                d.artifact.snapshot.display()
            ));
        }
    }
    err
}

/// Restaura cada subvolumen en `target` y deja una copia escribible con el
/// nombre de su etiqueta (`target/@`, `target/@home`…). Comprueba los hashes
/// de todas las cadenas antes de recibir nada.
pub fn restore_many(
    s: &mut Session,
    items: &[SubvolArtifact],
    target: &Path,
) -> Result<Vec<(String, Restored)>> {
    if items.is_empty() {
        bail!("no hay ningún subvolumen que restaurar");
    }
    let mut slugs = HashSet::new();
    for it in items {
        let slug = label_slug(&it.label)?;
        if !slugs.insert(slug.clone()) {
            bail!("dos subvolúmenes se restaurarían como {slug}");
        }
        for r in &it.chain {
            check_digest(r)
                .with_context(|| format!("subvolumen {}: no se ha restaurado nada", it.label))?;
        }
    }
    let mut out = Vec::new();
    for it in items {
        let slug = label_slug(&it.label)?;
        let r = restore(
            s,
            &RestoreOptions {
                streams: &it.chain,
                target,
                writable_name: Some(&slug),
            },
        )
        .with_context(|| format!("restaurando el subvolumen {}", it.label))?;
        out.push((it.label.clone(), r));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::Cmd;
    use crate::send::testutil::{btrfs, e2e_enabled, run, Cleanup};
    use crate::send::{send, SendPaths};
    use crate::types::{Artifact, Digest};
    use crate::verify::compare::compare_trees;

    #[test]
    fn slugs_and_names() {
        assert_eq!(subvol_name("sis-1", "@").unwrap(), "sis-1--@");
        assert_eq!(subvol_name("sis-1", "@home").unwrap(), "sis-1--@home");
        assert_eq!(subvol_name("sis-1", "var/log").unwrap(), "sis-1--var_log");
        for bad in ["", ".", ".."] {
            assert!(label_slug(bad).is_err());
        }
    }

    #[test]
    fn plan_rejects_clashes_and_empty() {
        let p = Path::new("/x");
        let sv = |label| SubvolSpec { label, source: p };
        assert!(plan_names("n", &[]).is_err());
        assert!(plan_names("n", &[sv("@"), sv("@")]).is_err());
        assert!(plan_names("n", &[sv("a/b"), sv("a_b")]).is_err());
        assert_eq!(
            plan_names("n", &[sv("@"), sv("@home")]).unwrap(),
            ["n--@", "n--@home"]
        );
    }

    fn fake(label: &str, dir: &Path, content: &[u8]) -> SubvolArtifact {
        let path = dir.join(format!("{label}.btrfs.zst"));
        std::fs::write(&path, content).unwrap();
        let digest = Digest::of_file(HashAlgo::Blake3, &path).unwrap();
        let artifact = Artifact {
            stream: path.clone(),
            snapshot: dir.join(format!(".partshield-{label}")),
            digest: digest.clone(),
            compressed_bytes: content.len() as u64,
            stream_bytes: 0,
            encryption: None,
            chunks: None,
        };
        SubvolArtifact {
            label: label.into(),
            source: dir.into(),
            parent: None,
            chain: vec![artifact.stream_ref()],
            artifact,
        }
    }

    #[test]
    fn previous_is_matched_by_label() {
        let dir = tempfile::tempdir().unwrap();
        let prev = [fake("@", dir.path(), b"a"), fake("@home", dir.path(), b"b")];
        assert_eq!(previous_for(&prev, "@home").unwrap().label, "@home");
        assert!(previous_for(&prev, "@var").is_none());
    }

    /// Un stream dañado en cualquier subvolumen para la restauración antes
    /// de ejecutar un solo comando.
    #[test]
    fn restore_many_checks_every_hash_first() {
        let dir = tempfile::tempdir().unwrap();
        let items = [fake("@", dir.path(), b"a"), fake("@home", dir.path(), b"b")];
        std::fs::write(&items[1].artifact.stream, b"x").unwrap();
        let mut s = Session::new(false);
        let err = restore_many(&mut s, &items, dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("dañado"), "{err:#}");
        assert!(s.records.is_empty());
    }

    /// `@` y `@home`, completa y luego incremental; restaura y compara.
    /// También los errores claros del padre de una incremental.
    #[test]
    fn e2e_multi_subvolume_incremental() {
        if !e2e_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut s = Session::new(false);
        let mut c = Cleanup::default();
        let (_, src) = btrfs(&mut s, &mut c, dir.path(), "origen");
        let (_, dst) = btrfs(&mut s, &mut c, dir.path(), "destino");

        let root = src.join("@");
        let home = src.join("@home");
        for sv in [&root, &home] {
            run(
                &mut s,
                Cmd::new("btrfs").arg("subvolume").arg("create").arg(sv),
            );
        }
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/hostname"), "partshield\n").unwrap();
        std::fs::write(home.join("notas.txt"), vec![7u8; 300_000]).unwrap();
        let snaps = src.join("snaps");
        std::fs::create_dir(&snaps).unwrap();
        let dest = dir.path().join("copias");
        let specs = [
            SubvolSpec {
                label: "@",
                source: &root,
            },
            SubvolSpec {
                label: "@home",
                source: &home,
            },
        ];
        let opts = |name, previous| MultiSendOptions {
            subvolumes: &specs,
            dest_dir: &dest,
            snapshot_dir: Some(&snaps),
            name,
            zstd_level: 3,
            hash: HashAlgo::Blake3,
            previous,
        };

        let full = send_many(&mut s, &opts("c1", &[])).unwrap();
        assert_eq!(full.len(), 2);
        assert!(full
            .iter()
            .all(|a| a.parent.is_none() && a.chain.len() == 1));

        std::fs::write(home.join("nuevo.txt"), "segunda copia\n").unwrap();
        std::fs::remove_file(root.join("etc/hostname")).unwrap();
        let incr = send_many(&mut s, &opts("c2", &full)).unwrap();
        for (i, f) in incr.iter().zip(&full) {
            assert_eq!(i.label, f.label);
            assert_eq!(i.parent.as_deref(), Some(f.artifact.snapshot.as_path()));
            assert_eq!(i.chain.len(), 2);
            assert_eq!(i.chain[0], f.artifact.stream_ref());
            assert!(i.artifact.stream_bytes < f.artifact.stream_bytes || i.label == "@");
        }

        let restored = restore_many(&mut s, &incr, &dst).unwrap();
        for ((label, r), i) in restored.iter().zip(&incr) {
            let cmp = compare_trees(&i.artifact.snapshot, &r.received).unwrap();
            assert!(cmp.identical(), "{label}: {:?}", cmp.differences);
            assert_eq!(r.writable.as_deref(), Some(dst.join(label).as_path()));
        }
        assert!(dst.join("@home/nuevo.txt").exists());
        assert!(!dst.join("@/etc/hostname").exists());

        // Padre escribible: error claro y nada a medias.
        let bad = |parent: &Path, name: &str, s: &mut Session| {
            let o = SendOptions {
                source: &home,
                dest_dir: &dest,
                snapshot_dir: Some(&snaps),
                name,
                zstd_level: 3,
                parent: Some(parent),
                hash: HashAlgo::Blake3,
            };
            let err = format!("{:#}", send(s, &o).unwrap_err());
            let p = SendPaths::for_options(&o);
            assert!(!p.stream.exists() && !p.partial.exists() && !p.snapshot.exists());
            err
        };
        let err = bad(&root, "c3", &mut s);
        assert!(err.contains("solo lectura"), "{err}");
        // Padre de solo lectura pero en otro Btrfs.
        let err = bad(&restored[1].1.received, "c4", &mut s);
        assert!(err.contains("mismo Btrfs"), "{err}");
        // Uno que falla a mitad (el segundo no es un subvolumen) no deja nada.
        let plain = src.join("normal");
        std::fs::create_dir(&plain).unwrap();
        let specs2 = [
            SubvolSpec {
                label: "@",
                source: &root,
            },
            SubvolSpec {
                label: "x",
                source: &plain,
            },
        ];
        let err = send_many(
            &mut s,
            &MultiSendOptions {
                subvolumes: &specs2,
                ..opts("c5", &[])
            },
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("no es un subvolumen"));
        assert!(!dest.join("c5--@.btrfs.zst").exists());
        assert!(!snaps.join(".partshield-c5--@").exists());
    }
}
