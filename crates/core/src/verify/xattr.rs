//! Extended attributes of a path, without following symlinks.
//!
//! std has no xattr API; glibc's `llistxattr`/`lgetxattr` are already linked
//! into every Rust binary on Linux, so they are declared here instead of
//! adding a dependency.

use std::collections::BTreeMap;
use std::ffi::{c_char, c_void, CString, OsString};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

extern "C" {
    fn llistxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize;
    fn lgetxattr(
        path: *const c_char,
        name: *const c_char,
        value: *mut c_void,
        size: usize,
    ) -> isize;
}

#[cfg(test)]
extern "C" {
    fn lsetxattr(
        path: *const c_char,
        name: *const c_char,
        value: *const c_void,
        size: usize,
        flags: i32,
    ) -> i32;
}

const ENODATA: i32 = 61;
const ERANGE: i32 = 34;
const ENOTSUP: i32 = 95;

pub type Xattrs = BTreeMap<OsString, Vec<u8>>;

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)
}

/// Calls `f(buf_ptr, buf_len)` with a growing buffer until the result fits.
fn read_sized(mut f: impl FnMut(*mut c_void, usize) -> isize) -> io::Result<Vec<u8>> {
    loop {
        let need = f(std::ptr::null_mut(), 0);
        if need < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; need as usize];
        let got = f(buf.as_mut_ptr().cast(), buf.len());
        if got >= 0 {
            buf.truncate(got as usize);
            return Ok(buf);
        }
        let err = io::Error::last_os_error();
        // Grew between the two calls: ask again.
        if err.raw_os_error() != Some(ERANGE) {
            return Err(err);
        }
    }
}

/// Every extended attribute of `path` (the link itself for a symlink).
/// A filesystem without xattr support yields an empty map.
pub fn read(path: &Path) -> io::Result<Xattrs> {
    let cpath = c_path(path)?;
    let names = match read_sized(|buf, len| {
        // SAFETY: `cpath` is NUL-terminated and `buf` is valid for `len` bytes
        // (or null with `len == 0`, which asks for the size).
        unsafe { llistxattr(cpath.as_ptr(), buf.cast(), len) }
    }) {
        Ok(n) => n,
        Err(e) if e.raw_os_error() == Some(ENOTSUP) => return Ok(Xattrs::new()),
        Err(e) => return Err(e),
    };
    let mut out = Xattrs::new();
    for name in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let cname = CString::new(name).map_err(io::Error::other)?;
        let value = match read_sized(|buf, len| {
            // SAFETY: as above; `cname` is NUL-terminated.
            unsafe { lgetxattr(cpath.as_ptr(), cname.as_ptr(), buf, len) }
        }) {
            Ok(v) => v,
            // Removed while we were reading the list.
            Err(e) if e.raw_os_error() == Some(ENODATA) => continue,
            Err(e) => return Err(e),
        };
        out.insert(OsString::from_vec(name.to_vec()), value);
    }
    Ok(out)
}

#[cfg(test)]
pub fn set(path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
    let cpath = c_path(path)?;
    let cname = CString::new(name).map_err(io::Error::other)?;
    // SAFETY: both strings are NUL-terminated and `value` is valid for its length.
    let r = unsafe {
        lsetxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Whether `dir`'s filesystem accepts `user.*` attributes.
#[cfg(test)]
pub fn user_xattrs_supported(dir: &Path) -> bool {
    let probe = dir.join(".xattr-probe");
    let ok = std::fs::write(&probe, "").is_ok() && set(&probe, "user.probe", b"1").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_what_was_set() {
        let dir = tempfile::tempdir().unwrap();
        if !user_xattrs_supported(dir.path()) {
            eprintln!("omitido: el sistema de archivos temporal no admite user.*");
            return;
        }
        let f = dir.path().join("f");
        std::fs::write(&f, "x").unwrap();
        assert!(read(&f).unwrap().is_empty());
        set(&f, "user.a", b"uno").unwrap();
        set(&f, "user.b", &[0u8; 300]).unwrap();
        let got = read(&f).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[&OsString::from("user.a")], b"uno");
        assert_eq!(got[&OsString::from("user.b")], vec![0u8; 300]);
    }
}
