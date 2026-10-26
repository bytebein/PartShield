//! Which files the content step hashes.
//!
//! The default sample is deterministic and reproducible: every file of the
//! reference gets a rank `BLAKE3(seed ‖ path)`, and files are taken in rank
//! order until **both** minimums are met:
//!
//! - at least [`MIN_FILES`] files, or [`MIN_FILE_PERCENT`] % of them if that
//!   is more;
//! - at least [`MIN_BYTES`] bytes.
//!
//! Each minimum is capped at what the reference has, so a tree below them is
//! hashed whole. The seed is the first 64 bits of the hash of the first
//! stream file, as computed while restoring it; it is written in the step's
//! detail so anyone can repeat the same selection.

use std::os::unix::ffi::OsStrExt;

use super::compare::FileRef;
use crate::types::Digest;

/// At least this many files are hashed (or all, if there are fewer).
pub const MIN_FILES: usize = 64;
/// … or this percentage of the files, if larger.
pub const MIN_FILE_PERCENT: usize = 1;
/// At least this many bytes are hashed (or all, if there are fewer).
pub const MIN_BYTES: u64 = 256 << 20;

/// How much content the last verification step hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContentSample {
    /// Deterministic sample with the minimums of this module.
    #[default]
    Sample,
    /// Every file.
    All,
}

/// First 64 bits of a digest, as the sampling seed.
pub fn seed_from(d: &Digest) -> u64 {
    let hex: String = d.hex.chars().take(16).collect();
    u64::from_str_radix(&hex, 16).unwrap_or(0)
}

fn rank(seed: u64, f: &FileRef) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&seed.to_le_bytes());
    h.update(f.path.as_os_str().as_bytes());
    *h.finalize().as_bytes()
}

/// Selected files, in the order they will be hashed.
pub fn select(files: &[FileRef], seed: u64, mode: ContentSample) -> Vec<FileRef> {
    if mode == ContentSample::All {
        return files.to_vec();
    }
    let total_bytes: u64 = files.iter().map(|f| f.size).sum();
    let want_files = MIN_FILES
        .max((files.len() * MIN_FILE_PERCENT).div_ceil(100))
        .min(files.len());
    let want_bytes = MIN_BYTES.min(total_bytes);

    let mut ranked: Vec<_> = files.iter().map(|f| (rank(seed, f), f)).collect();
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.path.cmp(&b.1.path)));

    let mut out = Vec::new();
    let mut bytes = 0;
    for (_, f) in ranked {
        if out.len() >= want_files && bytes >= want_bytes {
            break;
        }
        bytes += f.size;
        out.push(f.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HashAlgo;
    use std::path::PathBuf;

    fn files(n: usize, size: u64) -> Vec<FileRef> {
        (0..n)
            .map(|i| FileRef {
                path: PathBuf::from(format!("d/{i}")),
                size,
            })
            .collect()
    }

    fn bytes(v: &[FileRef]) -> u64 {
        v.iter().map(|f| f.size).sum()
    }

    #[test]
    fn seed_is_the_start_of_the_digest() {
        let d = Digest {
            algo: HashAlgo::Blake3,
            hex: "0123456789abcdefffff".into(),
        };
        assert_eq!(seed_from(&d), 0x0123_4567_89ab_cdef);
    }

    #[test]
    fn small_trees_are_hashed_whole() {
        let f = files(10, 1000);
        let mut got = select(&f, 7, ContentSample::Sample);
        got.sort_by(|a, b| a.path.cmp(&b.path));
        let mut all = f.clone();
        all.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(got, all);
        assert!(select(&[], 7, ContentSample::Sample).is_empty());
    }

    #[test]
    fn meets_both_minimums_and_no_more() {
        // 10 000 files of 1 MiB: 1 % is 100 files, but 256 MiB needs 256.
        let f = files(10_000, 1 << 20);
        let got = select(&f, 42, ContentSample::Sample);
        assert_eq!(got.len(), 256);
        assert_eq!(bytes(&got), MIN_BYTES);

        // 20 000 tiny files: bytes run out, so it is all of them…
        let tiny = files(20_000, 10);
        assert_eq!(select(&tiny, 1, ContentSample::Sample).len(), 20_000);
        // …but with large files the count rule decides: 1 % of 20 000.
        let big = files(20_000, 1 << 30);
        assert_eq!(select(&big, 1, ContentSample::Sample).len(), 200);
        // And below 6 400 files the floor of 64 applies.
        let few = files(1_000, 1 << 30);
        assert_eq!(select(&few, 1, ContentSample::Sample).len(), MIN_FILES);
    }

    #[test]
    fn reproducible_and_seed_dependent() {
        let f = files(5_000, 1 << 20);
        let a = select(&f, 99, ContentSample::Sample);
        let mut shuffled = f.clone();
        shuffled.reverse();
        assert_eq!(a, select(&shuffled, 99, ContentSample::Sample));
        assert_ne!(a, select(&f, 100, ContentSample::Sample));
    }

    #[test]
    fn all_means_all() {
        let f = files(5_000, 1 << 20);
        assert_eq!(select(&f, 3, ContentSample::All), f);
    }
}
