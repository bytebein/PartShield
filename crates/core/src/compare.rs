//! Compares two directory trees: types, sizes, permissions, owners,
//! symlink targets and file contents (BLAKE3).

use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    File { size: u64, hash: [u8; 32] },
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
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Comparison {
    pub entries: usize,
    pub files: usize,
    pub bytes: u64,
    /// First differences found (capped at `MAX_DIFFS`).
    pub differences: Vec<String>,
    pub total_differences: usize,
}

impl Comparison {
    pub fn identical(&self) -> bool {
        self.total_differences == 0
    }
}

const MAX_DIFFS: usize = 50;

pub fn compare_trees(expected: &Path, actual: &Path) -> Result<Comparison> {
    let a = scan(expected)?;
    let b = scan(actual)?;
    let mut cmp = Comparison::default();
    let diff = |cmp: &mut Comparison, msg: String| {
        cmp.total_differences += 1;
        if cmp.differences.len() < MAX_DIFFS {
            cmp.differences.push(msg);
        }
    };

    for (path, ea) in &a {
        cmp.entries += 1;
        if let Kind::File { size, .. } = ea.kind {
            cmp.files += 1;
            cmp.bytes += size;
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
    Ok(cmp)
}

fn describe(path: &Path, a: &Entry, b: &Entry) -> String {
    let p = path.display();
    match (&a.kind, &b.kind) {
        (Kind::File { size: sa, .. }, Kind::File { size: sb, .. }) if sa != sb => {
            format!("tamaño distinto en {p}: {sa} → {sb}")
        }
        (Kind::File { .. }, Kind::File { .. }) if a.kind != b.kind => {
            format!("contenido distinto en {p}")
        }
        (ka, kb) if std::mem::discriminant(ka) != std::mem::discriminant(kb) => {
            format!("tipo distinto en {p}")
        }
        (Kind::Symlink(_), Kind::Symlink(_)) if a.kind != b.kind => {
            format!("destino del enlace distinto en {p}")
        }
        _ if a.mode != b.mode => format!("permisos distintos en {p}: {:o} → {:o}", a.mode, b.mode),
        _ => format!(
            "propietario distinto en {p}: {}:{} → {}:{}",
            a.uid, a.gid, b.uid, b.gid
        ),
    }
}

fn scan(root: &Path) -> Result<BTreeMap<PathBuf, Entry>> {
    let mut out = BTreeMap::new();
    for item in WalkDir::new(root).follow_links(false).min_depth(1) {
        let item = item.with_context(|| format!("recorriendo {}", root.display()))?;
        let md = item.path().symlink_metadata()?;
        let ft = md.file_type();
        let kind = if ft.is_symlink() {
            Kind::Symlink(std::fs::read_link(item.path())?)
        } else if ft.is_dir() {
            Kind::Dir
        } else if ft.is_file() {
            Kind::File {
                size: md.len(),
                hash: hash_file(item.path())?,
            }
        } else {
            Kind::Other(md.mode() & 0o170000)
        };
        let rel = item
            .path()
            .strip_prefix(root)
            .expect("walkdir yields children")
            .to_path_buf();
        out.insert(
            rel,
            Entry {
                kind,
                mode: md.mode() & 0o7777,
                uid: md.uid(),
                gid: md.gid(),
            },
        );
    }
    Ok(out)
}

fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let mut h = blake3::Hasher::new();
    let f = File::open(path).with_context(|| format!("abriendo {}", path.display()))?;
    h.update_reader(f)?;
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
    }

    #[test]
    fn identical_trees() {
        let (x, y) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        tree(x.path());
        tree(y.path());
        let c = compare_trees(x.path(), y.path()).unwrap();
        assert!(c.identical(), "{:?}", c.differences);
        assert_eq!((c.files, c.bytes), (2, 1004));
    }

    #[test]
    fn detects_every_kind_of_difference() {
        let (x, y) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        tree(x.path());
        tree(y.path());
        fs::write(y.path().join("docs/a.txt"), "HOLA").unwrap();
        fs::remove_file(y.path().join("b.bin")).unwrap();
        fs::write(y.path().join("extra"), "").unwrap();
        fs::set_permissions(y.path().join("docs"), fs::Permissions::from_mode(0o700)).unwrap();
        let c = compare_trees(x.path(), y.path()).unwrap();
        let all = c.differences.join("\n");
        assert_eq!(c.total_differences, 4, "{all}");
        assert!(all.contains("contenido distinto en docs/a.txt"));
        assert!(all.contains("falta en la copia: b.bin"));
        assert!(all.contains("sobra en la copia: extra"));
        assert!(all.contains("permisos distintos en docs"));
    }
}
