//! Ayudas para las pruebas con root de `send/`: loop devices y montajes que
//! se liberan siempre, también si la prueba falla.

use std::path::{Path, PathBuf};

use crate::cmd::{sandboxed, Cmd, Session};

/// `true` si hay que ejecutar las pruebas con root. Sin `PARTSHIELD_E2E=1`
/// la prueba sale sin hacer nada; con él, exige `PARTSHIELD_SANDBOX=1`.
pub fn e2e_enabled() -> bool {
    if !std::env::var_os("PARTSHIELD_E2E").is_some_and(|v| v == "1") {
        eprintln!("PARTSHIELD_E2E no está a 1: prueba omitida");
        return false;
    }
    assert!(
        sandboxed(),
        "las pruebas con root exigen PARTSHIELD_SANDBOX=1 (solo loop devices)"
    );
    true
}

pub fn run(s: &mut Session, cmd: Cmd) -> String {
    let shown = cmd.to_string();
    s.run(cmd)
        .unwrap_or_else(|e| panic!("{shown}: {e:#}"))
        .trim()
        .to_string()
}

/// Imagen de disco vacía (dispersa) de `bytes`.
pub fn image(path: &Path, bytes: u64) {
    std::fs::File::create(path).unwrap().set_len(bytes).unwrap();
}

/// Loop devices y montajes creados por una prueba. Al soltarse desmonta
/// (en orden inverso) y desconecta todo.
#[derive(Default)]
pub struct Cleanup {
    mounts: Vec<PathBuf>,
    loops: Vec<String>,
}

impl Cleanup {
    /// Conecta `img` (o un trozo suyo) a un loop device nuevo.
    pub fn attach(&mut self, s: &mut Session, img: &Path, range: Option<(u64, u64)>) -> String {
        let mut cmd = Cmd::new("losetup").arg("--find").arg("--show");
        if let Some((offset, size)) = range {
            cmd = cmd
                .arg("--offset")
                .arg(offset.to_string())
                .arg("--sizelimit")
                .arg(size.to_string());
        }
        let dev = run(s, cmd.arg(img));
        assert!(dev.starts_with("/dev/loop"), "losetup devolvió {dev}");
        self.loops.push(dev.clone());
        dev
    }

    /// Conecta un disco entero con `--partscan` (el kernel lee su tabla).
    pub fn attach_partscan(&mut self, s: &mut Session, img: &Path) -> String {
        let dev = run(
            s,
            Cmd::new("losetup")
                .arg("--find")
                .arg("--show")
                .arg("--partscan")
                .arg(img),
        );
        assert!(dev.starts_with("/dev/loop"), "losetup devolvió {dev}");
        self.loops.push(dev.clone());
        dev
    }

    pub fn detach(&mut self, s: &mut Session, dev: &str) {
        run(s, Cmd::new("losetup").arg("--detach").arg(dev));
        self.loops.retain(|d| d != dev);
    }

    pub fn mount(&mut self, s: &mut Session, dev: &str, at: &Path) {
        std::fs::create_dir_all(at).unwrap();
        run(s, Cmd::new("mount").arg(dev).arg(at));
        self.mounts.push(at.to_path_buf());
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let mut s = Session::new(false);
        for m in self.mounts.drain(..).rev() {
            let _ = s.run(Cmd::new("umount").arg(&m));
        }
        for l in self.loops.drain(..).rev() {
            let _ = s.run(Cmd::new("losetup").arg("--detach").arg(&l));
        }
    }
}

/// Un Btrfs nuevo con `BLOCK_GROUP_TREE` en una imagen de `dir`, montado.
pub fn btrfs(s: &mut Session, c: &mut Cleanup, dir: &Path, name: &str) -> (String, PathBuf) {
    let img = dir.join(format!("{name}.img"));
    image(&img, 1 << 30);
    run(
        s,
        Cmd::new("mkfs.btrfs")
            .arg("-q")
            .arg("-O")
            .arg("block-group-tree")
            .arg(&img),
    );
    let dev = c.attach(s, &img, None);
    let mnt = dir.join(format!("{name}-mnt"));
    c.mount(s, &dev, &mnt);
    (dev, mnt)
}
