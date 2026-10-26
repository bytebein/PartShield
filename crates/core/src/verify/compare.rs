//! Compares two directory trees.
//!
//! - [`compare_metadata`]: the whole tree (the root included): types, sizes,
//!   permissions, owners, link counts, symlink targets and extended
//!   attributes. It reads no file contents, so it is cheap on any size.
//! - [`compare_content`]: BLAKE3 of the contents of the given files.
//! - [`compare_trees`]: both, over every file.

use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use walkdir::WalkDir;

use super::xattr::{self, Xattrs};
use crate::types::Comparison;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    File { size: u64 },
    Dir,
    Symlink(PathBuf),
    Other(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    kind: Kind,
    mode: u32,
    uid: u32,
    gid: u32,
    /// Hard link count; `None` for directories, whose count depends on the
    /// filesystem rather than on the data.
    nlink: Option<u64>,
    xattrs: Xattrs,
}

/// A regular file of the reference tree, relative to its root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRef {
    pub path: PathBuf,
    pub size: u64,
}

/// Result of [`compare_metadata`]: the comparison and the regular files of
/// the expected tree, so contents can be checked without walking it again.
#[derive(Debug, Clone)]
pub struct MetadataComparison {
    pub comparison: Comparison,
    pub files: Vec<FileRef>,
}

pub const MAX_DIFFS: usize = 50;

fn diff(cmp: &mut Comparison, msg: String) {
    cmp.total_differences += 1;
    if cmp.differences.len() < MAX_DIFFS {
        cmp.differences.push(msg);
    }
}

/// Adds the differences of `other` to `into` (counts are left alone).
pub fn absorb(into: &mut Comparison, other: &Comparison) {
    let room = MAX_DIFFS.saturating_sub(into.differences.len());
    into.differences
        .extend(other.differences.iter().take(room).cloned());
    into.total_differences += other.total_differences;
}

pub fn compare_metadata(expected: &Path, actual: &Path) -> Result<MetadataComparison> {
    let a = scan(expected)?;
    let b = scan(actual)?;
    let mut cmp = Comparison::default();
    let mut files = Vec::new();

    for (path, ea) in &a {
        cmp.entries += 1;
        if let Kind::File { size } = ea.kind {
            cmp.files += 1;
            cmp.bytes += size;
            files.push(FileRef {
                path: path.clone(),
                size,
            });
        }
        match b.get(path) {
            None => diff(&mut cmp, format!("falta en la copia: {}", path.display())),
            Some(eb) if eb != ea => diff(&mut cmp, describe(path, ea, eb)),
            Some(_) => {}
        }
    }
    for path in b.keys().filter(|p| !a.contains_key(*p)) {
        diff(&mut cmp, format!("sobra en la copia: {}", path.display()));
    }
    Ok(MetadataComparison {
        comparison: cmp,
        files,
    })
}

/// Hashes `files` (relative paths) under both roots and reports any
/// difference, including files that cannot be read (e.g. EIO from a bad
/// checksum on the copy).
pub fn compare_content(expected: &Path, actual: &Path, files: &[FileRef]) -> Comparison {
    let mut cmp = Comparison::default();
    for f in files {
        cmp.entries += 1;
        cmp.files += 1;
        cmp.bytes += f.size;
        let p = f.path.display();
        let want = match hash_file(&expected.join(&f.path)) {
            Ok(h) => h,
            Err(e) => {
                diff(
                    &mut cmp,
                    format!("no se pudo leer {p} en la referencia: {e:#}"),
                );
                continue;
            }
        };
        match hash_file(&actual.join(&f.path)) {
            Ok(got) if got == want => {}
            Ok(_) => diff(&mut cmp, format!("contenido distinto en {p}")),
            Err(e) => diff(&mut cmp, format!("no se pudo leer {p} en la copia: {e:#}")),
        }
    }
    cmp
}

/// Metadata of the whole tree and contents of every file.
pub fn compare_trees(expected: &Path, actual: &Path) -> Result<Comparison> {
    let MetadataComparison {
        mut comparison,
        files,
    } = compare_metadata(expected, actual)?;
    absorb(&mut comparison, &compare_content(expected, actual, &files));
    Ok(comparison)
}

fn describe(path: &Path, a: &Entry, b: &Entry) -> String {
    let p = path.display();
    match (&a.kind, &b.kind) {
        (Kind::File { size: sa }, Kind::File { size: sb }) if sa != sb => {
            format!("tamaño distinto en {p}: {sa} → {sb}")
        }
        (ka, kb) if std::mem::discriminant(ka) != std::mem::discriminant(kb) => {
            format!("tipo distinto en {p}")
        }
        (Kind::Symlink(_), Kind::Symlink(_)) if a.kind != b.kind => {
            format!("destino del enlace distinto en {p}")
        }
        (Kind::Other(_), Kind::Other(_)) if a.kind != b.kind => format!("tipo distinto en {p}"),
        _ if a.mode != b.mode => format!("permisos distintos en {p}: {:o} → {:o}", a.mode, b.mode),
        _ if (a.uid, a.gid) != (b.uid, b.gid) => format!(
            "propietario distinto en {p}: {}:{} → {}:{}",
            a.uid, a.gid, b.uid, b.gid
        ),
        _ if a.nlink != b.nlink => format!(
            "número de enlaces duros distinto en {p}: {} → {}",
            a.nlink.unwrap_or(0),
            b.nlink.unwrap_or(0)
        ),
        _ => {
            let names = a
                .xattrs
                .keys()
                .chain(b.xattrs.keys())
                .filter(|k| a.xattrs.get(*k) != b.xattrs.get(*k))
                .map(|k| k.to_string_lossy().into_owned())
                .collect::<std::collections::BTreeSet<_>>();
            format!(
                "atributos extendidos distintos en {p}: {}",
                names.into_iter().collect::<Vec<_>>().join(", ")
            )
        }
    }
}

fn scan(root: &Path) -> Result<BTreeMap<PathBuf, Entry>> {
    let mut out = BTreeMap::new();
    for item in WalkDir::new(root).follow_links(false) {
        let item = item.with_context(|| format!("recorriendo {}", root.display()))?;
        let path = item.path();
        let md = path
            .symlink_metadata()
            .with_context(|| format!("leyendo los metadatos de {}", path.display()))?;
        let ft = md.file_type();
        let kind = if ft.is_symlink() {
            Kind::Symlink(std::fs::read_link(path)?)
        } else if ft.is_dir() {
            Kind::Dir
        } else if ft.is_file() {
            Kind::File { size: md.len() }
        } else {
            Kind::Other(md.mode() & 0o170000)
        };
        let rel = path.strip_prefix(root).expect("walkdir yields children");
        let rel = if rel.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            rel.to_path_buf()
        };
        out.insert(
            rel,
            Entry {
                nlink: (!ft.is_dir()).then(|| md.nlink()),
                kind,
                mode: md.mode() & 0o7777,
                uid: md.uid(),
                gid: md.gid(),
                xattrs: xattr::read(path).with_context(|| {
                    format!("leyendo los atributos extendidos de {}", path.display())
                })?,
            },
        );
    }
    Ok(out)
}

fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let mut h = blake3::Hasher::new();
    let f = File::open(path).with_context(|| format!("abriendo {}", path.display()))?;
    h.update_reader(f)
        .with_context(|| format!("leyendo {}", path.display()))?;
    Ok(*h.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn tree(root: &Path) {
        fs::create_dir_all(root.join("docs")).unwrap();
        fs::write(root.join("docs/a.txt"), "hola").unwrap();
        fs::write(root.join("b.bin"), [0u8; 1000]).unwrap();
        symlink("docs/a.txt", root.join("enlace")).unwrap();
        fs::hard_link(root.join("b.bin"), root.join("docs/duro")).unwrap();
    }

    fn pair() -> (tempfile::TempDir, tempfile::TempDir) {
        let (x, y) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        tree(x.path());
        tree(y.path());
        (x, y)
    }

    #[test]
    fn identical_trees() {
        let (x, y) = pair();
        let c = compare_trees(x.path(), y.path()).unwrap();
        assert!(c.identical(), "{:?}", c.differences);
        assert_eq!((c.files, c.bytes), (3, 2004));
        let m = compare_metadata(x.path(), y.path()).unwrap();
        assert_eq!(m.comparison.entries, 6, "la raíz también cuenta");
        let paths: Vec<_> = m.files.iter().map(|f| f.path.to_str().unwrap()).collect();
        assert_eq!(paths, ["b.bin", "docs/a.txt", "docs/duro"]);
    }

    #[test]
    fn metadata_detects_every_kind_of_difference() {
        let (x, y) = pair();
        let y = y.path();
        fs::write(y.join("docs/a.txt"), "hola!").unwrap();
        fs::remove_file(y.join("enlace")).unwrap();
        symlink("b.bin", y.join("enlace")).unwrap();
        fs::write(y.join("extra"), "").unwrap();
        fs::set_permissions(y.join("docs"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_file(y.join("docs/duro")).unwrap();
        fs::write(y.join("docs/duro"), [0u8; 1000]).unwrap();
        let c = compare_metadata(x.path(), y).unwrap().comparison;
        let all = c.differences.join("\n");
        assert_eq!(c.total_differences, 6, "{all}");
        assert!(all.contains("tamaño distinto en docs/a.txt: 4 → 5"));
        assert!(all.contains("destino del enlace distinto en enlace"));
        assert!(all.contains("sobra en la copia: extra"));
        assert!(all.contains("permisos distintos en docs:"));
        // b.bin and docs/duro are no longer hard links to each other.
        assert!(all.contains("enlaces duros distinto en b.bin: 2 → 1"));
        assert!(all.contains("enlaces duros distinto en docs/duro: 2 → 1"));
    }

    #[test]
    fn metadata_sees_missing_files_and_the_root() {
        let (x, y) = pair();
        fs::remove_file(y.path().join("b.bin")).unwrap();
        fs::set_permissions(y.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(x.path(), fs::Permissions::from_mode(0o750)).unwrap();
        let c = compare_metadata(x.path(), y.path()).unwrap().comparison;
        let all = c.differences.join("\n");
        assert!(all.contains("falta en la copia: b.bin"), "{all}");
        assert!(all.contains("permisos distintos en .: 750 → 755"), "{all}");
    }

    #[test]
    fn metadata_detects_xattrs() {
        let (x, y) = pair();
        if !xattr::user_xattrs_supported(x.path()) {
            eprintln!("omitido: el sistema de archivos temporal no admite user.*");
            return;
        }
        xattr::set(&x.path().join("b.bin"), "user.etiqueta", b"azul").unwrap();
        xattr::set(&y.path().join("b.bin"), "user.etiqueta", b"azul").unwrap();
        assert!(compare_metadata(x.path(), y.path())
            .unwrap()
            .comparison
            .identical());
        xattr::set(&y.path().join("b.bin"), "user.etiqueta", b"rojo").unwrap();
        let c = compare_metadata(x.path(), y.path()).unwrap().comparison;
        assert_eq!(
            c.differences,
            [
                "atributos extendidos distintos en b.bin: user.etiqueta",
                // Same inode: a hard link shares its attributes.
                "atributos extendidos distintos en docs/duro: user.etiqueta",
            ]
        );
    }

    #[test]
    fn content_is_left_to_the_content_check() {
        let (x, y) = pair();
        fs::write(y.path().join("docs/a.txt"), "HOLA").unwrap();
        let m = compare_metadata(x.path(), y.path()).unwrap();
        assert!(m.comparison.identical(), "same size: metadata cannot tell");
        let c = compare_content(x.path(), y.path(), &m.files);
        assert_eq!(c.differences, ["contenido distinto en docs/a.txt"]);
        assert_eq!((c.files, c.bytes), (3, 2004));
        let only_b = compare_content(x.path(), y.path(), &m.files[..1]);
        assert!(only_b.identical());
        let full = compare_trees(x.path(), y.path()).unwrap();
        assert_eq!(full.differences, ["contenido distinto en docs/a.txt"]);
    }

    #[test]
    fn content_reports_unreadable_files() {
        let (x, y) = pair();
        let m = compare_metadata(x.path(), y.path()).unwrap();
        fs::remove_file(y.path().join("b.bin")).unwrap();
        let c = compare_content(x.path(), y.path(), &m.files);
        assert_eq!(c.total_differences, 1);
        assert!(c.differences[0].starts_with("no se pudo leer b.bin en la copia"));
    }

    #[test]
    fn absorb_caps_the_list_but_not_the_count() {
        let mut a = Comparison {
            differences: vec!["x".into(); MAX_DIFFS - 1],
            total_differences: MAX_DIFFS - 1,
            ..Default::default()
        };
        let b = Comparison {
            differences: vec!["y".into(); 3],
            total_differences: 7,
            ..Default::default()
        };
        absorb(&mut a, &b);
        assert_eq!(a.differences.len(), MAX_DIFFS);
        assert_eq!(a.total_differences, MAX_DIFFS - 1 + 7);
    }
}
