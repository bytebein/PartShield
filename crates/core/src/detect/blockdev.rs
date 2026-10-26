//! Block layers under the filesystem: dm-crypt/LUKS, LVM, partitions, disks
//! and loop devices.
//!
//! The stack comes from `lsblk -J -s` (inverse tree: from the device down to
//! the disks it sits on). lsblk takes UUID and FSTYPE from the udev database,
//! so where it has none (containers, rescue systems without udev) they are
//! probed with `blkid -p`. LUKS headers are confirmed by reading their magic
//! directly (`LUKS\xba\xbe` for the primary header, `SKUL\xba\xbe` for the
//! LUKS2 secondary one), through `cmd::guard_path`.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::cmd::{Cmd, Session};
use crate::types::{BlockLayer, BlockStack, LayerKind};

pub const LUKS_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";
pub const LUKS2_SECONDARY_MAGIC: &[u8; 6] = b"SKUL\xba\xbe";
/// Where a LUKS2 secondary header can start (it follows the primary, whose
/// size is one of these): cryptsetup `hdr_checks`.
pub const LUKS2_SECONDARY_OFFSETS: [u64; 9] = [
    0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x10_0000, 0x20_0000, 0x40_0000,
];
const LUKS_UUID_OFFSET: usize = 168;
const LUKS_UUID_LEN: usize = 40;
const LUKS_READ: usize = 512;

// ------------------------------------------------------------------ lsblk

#[derive(Debug, Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<LsblkDev>,
}

#[derive(Debug, Deserialize)]
struct LsblkDev {
    name: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    fstype: Option<String>,
    /// With `-s` these are the devices this one sits on.
    #[serde(default)]
    children: Vec<LsblkDev>,
}

/// One device of the stack before it becomes a `BlockLayer`.
#[derive(Debug, Clone)]
struct Node {
    name: String,
    device: PathBuf,
    lsblk_type: String,
    /// UUID of what is stored on the device (lsblk or blkid).
    uuid: Option<String>,
    fstype: Option<String>,
    /// Indexes of the nodes this one sits on.
    below: Vec<usize>,
    /// LUKS header read from the device, if any.
    luks: Option<LuksHeader>,
    notes: Vec<String>,
}

fn kind_of(lsblk_type: &str) -> LayerKind {
    match lsblk_type {
        "disk" => LayerKind::Disk,
        "part" => LayerKind::Partition,
        "crypt" => LayerKind::Luks,
        "lvm" => LayerKind::LvmLv,
        "loop" => LayerKind::Loop,
        _ => LayerKind::Other,
    }
}

fn nonempty(s: &Option<String>) -> Option<String> {
    s.clone().filter(|v| !v.is_empty())
}

fn parse_nodes(json: &str) -> Result<Vec<Node>> {
    let out: LsblkOutput = serde_json::from_str(json).context("salida de lsblk no válida")?;
    let mut nodes = Vec::new();
    for dev in &out.blockdevices {
        add_node(dev, &mut nodes);
    }
    Ok(nodes)
}

/// Depth first; returns the node's index. A device reached twice is listed
/// once.
fn add_node(dev: &LsblkDev, nodes: &mut Vec<Node>) -> usize {
    let device = PathBuf::from(nonempty(&dev.path).unwrap_or_else(|| format!("/dev/{}", dev.name)));
    if let Some(i) = nodes.iter().position(|n| n.device == device) {
        return i;
    }
    let i = nodes.len();
    nodes.push(Node {
        name: dev.name.clone(),
        device,
        lsblk_type: dev.kind.clone().unwrap_or_default(),
        uuid: nonempty(&dev.uuid),
        fstype: nonempty(&dev.fstype),
        below: Vec::new(),
        luks: None,
        notes: Vec::new(),
    });
    let below = dev.children.iter().map(|c| add_node(c, nodes)).collect();
    nodes[i].below = below;
    i
}

fn build(nodes: &[Node]) -> BlockStack {
    let layers = nodes
        .iter()
        .map(|n| {
            let kind = kind_of(&n.lsblk_type);
            let mut detail = Vec::new();
            let mut uuid = n.uuid.clone();
            match kind {
                LayerKind::Luks => {
                    detail.push(format!("dm-crypt {}", n.name));
                    let header =
                        n.below.iter().map(|&b| &nodes[b]).find(|b| {
                            b.luks.is_some() || b.fstype.as_deref() == Some("crypto_LUKS")
                        });
                    match header {
                        Some(h) => {
                            uuid = h.luks.as_ref().map(|l| l.uuid.clone()).or(h.uuid.clone());
                            detail.push(format!("cabecera LUKS en {}", h.device.display()));
                        }
                        // Plain dm-crypt, or a detached header.
                        None => detail.push("sin cabecera LUKS en el dispositivo de abajo".into()),
                    }
                }
                LayerKind::LvmLv => detail.push(format!("LV {}", n.name)),
                LayerKind::Other => detail.push(format!("tipo {}", n.lsblk_type)),
                _ => {}
            }
            if let Some(fs) = &n.fstype {
                detail.push(format!("contiene {fs}"));
            }
            if let Some(h) = &n.luks {
                detail.push(h.describe());
            }
            if n.below.len() > 1 {
                let names: Vec<&str> = n.below.iter().map(|&b| nodes[b].name.as_str()).collect();
                detail.push(format!("sobre {}", names.join(", ")));
            }
            detail.extend(n.notes.iter().cloned());
            BlockLayer {
                kind,
                device: n.device.clone(),
                uuid,
                detail: Some(detail.join("; ")).filter(|d| !d.is_empty()),
            }
        })
        .collect();
    BlockStack { layers }
}

/// Builds the stack from `lsblk -J -s -o NAME,PATH,TYPE,UUID,FSTYPE,PKNAME`
/// output. Pure: no device is touched.
///
/// Layers go from the device holding the filesystem down to the disks, depth
/// first; a device sitting on several (LVM over two PVs, RAID) lists every
/// branch in turn.
///
/// `uuid` is the UUID of what is stored on that device, except for a `Luks`
/// layer, which takes the LUKS header's UUID from the device below it.
pub fn parse_lsblk(json: &str) -> Result<BlockStack> {
    Ok(build(&parse_nodes(json)?))
}

/// `(UUID, TYPE)` from `blkid -p -o export` output. Pure.
pub fn parse_blkid_export(out: &str) -> (Option<String>, Option<String>) {
    let get = |key: &str| {
        out.lines()
            .filter_map(|l| l.split_once('='))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
            .filter(|v| !v.is_empty())
    };
    (get("UUID"), get("TYPE"))
}

/// Layers under `dev`, from `dev` itself down to the disk.
pub fn block_stack(s: &mut Session, dev: &Path) -> Result<BlockStack> {
    let json = s.run(
        Cmd::new("lsblk")
            .arg("-J")
            .arg("-s")
            .arg("-o")
            .arg("NAME,PATH,TYPE,UUID,FSTYPE,PKNAME")
            .arg(dev),
    )?;
    let mut nodes = parse_nodes(&json)?;
    for n in &mut nodes {
        if n.fstype.is_none() {
            // Exit code 2 means "nothing found", which is fine.
            let blkid = Cmd::new("blkid")
                .arg("-p")
                .arg("-o")
                .arg("export")
                .arg(&n.device);
            let out = s.run_unchecked(&blkid)?;
            if out.success {
                let (uuid, fstype) = parse_blkid_export(&out.stdout);
                n.uuid = n.uuid.take().or(uuid);
                n.fstype = fstype;
            }
        }
        // Any device may hold a LUKS header (LUKS on LVM puts it on an LV),
        // so read them all; a read error matters only where one was expected.
        let expected = n.fstype.as_deref() == Some("crypto_LUKS");
        match luks_header(&n.device) {
            Ok(None) if expected => n
                .notes
                .push("dice crypto_LUKS pero no hay magic LUKS".into()),
            Ok(h) => n.luks = h,
            Err(e) if expected => n.notes.push(format!("cabecera LUKS no leída: {e:#}")),
            Err(_) => {}
        }
    }
    Ok(build(&nodes))
}

// ------------------------------------------------------------ cabecera LUKS

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LuksHeader {
    /// 1 or 2.
    pub version: u16,
    pub uuid: String,
    /// The primary header (offset 0) is intact.
    pub primary: bool,
    /// Offset of the LUKS2 secondary header, if found.
    pub secondary: Option<u64>,
}

impl LuksHeader {
    pub fn describe(&self) -> String {
        let mut s = format!("cabecera LUKS{} uuid {}", self.version, self.uuid);
        match (self.primary, self.secondary) {
            (true, Some(off)) => s.push_str(&format!(", secundaria en {off:#x}")),
            (true, None) if self.version == 2 => s.push_str(", sin cabecera secundaria"),
            (false, Some(off)) => s.push_str(&format!(
                ", ¡solo queda la cabecera secundaria (en {off:#x})!"
            )),
            _ => {}
        }
        s
    }
}

/// One header block: `Some((is_primary, version, uuid))` if it starts with
/// a LUKS magic.
pub fn parse_luks_block(buf: &[u8]) -> Option<(bool, u16, String)> {
    if buf.len() < LUKS_UUID_OFFSET + LUKS_UUID_LEN {
        return None;
    }
    let primary = match &buf[..6] {
        m if m == LUKS_MAGIC => true,
        m if m == LUKS2_SECONDARY_MAGIC => false,
        _ => return None,
    };
    let version = u16::from_be_bytes([buf[6], buf[7]]);
    let raw = &buf[LUKS_UUID_OFFSET..LUKS_UUID_OFFSET + LUKS_UUID_LEN];
    let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Some((
        primary,
        version,
        String::from_utf8_lossy(&raw[..len]).into_owned(),
    ))
}

/// Reads the LUKS header of `path` (device or image file), if there is one.
pub fn luks_header(path: &Path) -> Result<Option<LuksHeader>> {
    crate::cmd::guard_path(path)?;
    let mut f = File::open(path).with_context(|| format!("abriendo {}", path.display()))?;
    let size = f.seek(SeekFrom::End(0))?;
    let mut read = |off: u64| -> Result<Option<Vec<u8>>> {
        if off + LUKS_READ as u64 > size {
            return Ok(None);
        }
        let mut buf = vec![0u8; LUKS_READ];
        f.seek(SeekFrom::Start(off))?;
        f.read_exact(&mut buf)
            .with_context(|| format!("leyendo {} en {off:#x}", path.display()))?;
        Ok(Some(buf))
    };

    let primary = read(0)?
        .as_deref()
        .and_then(parse_luks_block)
        .filter(|(p, _, _)| *p);
    let mut secondary = None;
    if !matches!(primary, Some((_, v, _)) if v != 2) {
        for off in LUKS2_SECONDARY_OFFSETS {
            if let Some((false, v, uuid)) = read(off)?.as_deref().and_then(parse_luks_block) {
                secondary = Some((off, v, uuid));
                break;
            }
        }
    }
    Ok(match (primary, secondary) {
        (Some((_, version, uuid)), sec) => Some(LuksHeader {
            version,
            uuid,
            primary: true,
            secondary: sec.map(|(off, _, _)| off),
        }),
        (None, Some((off, version, uuid))) => Some(LuksHeader {
            version,
            uuid,
            primary: false,
            secondary: Some(off),
        }),
        (None, None) => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ------------------------------------------------- lsblk (JSON de ejemplo)

    /// `lsblk -J -s` on a Btrfs inside LUKS2 on a GPT partition.
    const LUKS_ON_PART: &str = r#"{
       "blockdevices": [
          {"name":"luks-3f0c", "path":"/dev/mapper/luks-3f0c", "type":"crypt",
           "uuid":"856546ef-38b5-4081-8dbd-85ec99b72676", "fstype":"btrfs", "pkname":"nvme0n1p2",
             "children": [
                {"name":"nvme0n1p2", "path":"/dev/nvme0n1p2", "type":"part",
                 "uuid":"3f0c1a2b-1111-2222-3333-444455556666", "fstype":"crypto_LUKS", "pkname":"nvme0n1",
                   "children": [
                      {"name":"nvme0n1", "path":"/dev/nvme0n1", "type":"disk",
                       "uuid":null, "fstype":null, "pkname":null}
                   ]
                }
             ]
          }
       ]
    }"#;

    /// LVM on LUKS on a loop device (what the integration test builds).
    const LVM_ON_LUKS: &str = r#"{
       "blockdevices": [
          {"name":"partshield--test--42--vg-lv", "path":"/dev/mapper/partshield--test--42--vg-lv",
           "type":"lvm", "uuid":"11111111-2222-3333-4444-555555555555", "fstype":"btrfs", "pkname":"dm-0",
             "children": [
                {"name":"partshield-test-42-crypt", "path":"/dev/mapper/partshield-test-42-crypt",
                 "type":"crypt", "uuid":"AbCdEf-pv", "fstype":"LVM2_member", "pkname":"loop7",
                   "children": [
                      {"name":"loop7", "path":"/dev/loop7", "type":"loop",
                       "uuid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "fstype":"crypto_LUKS", "pkname":null}
                   ]
                }
             ]
          }
       ]
    }"#;

    const PLAIN_LOOP: &str = r#"{
       "blockdevices": [
          {"name":"loop3", "path":"/dev/loop3", "type":"loop",
           "uuid":"856546ef-38b5-4081-8dbd-85ec99b72676", "fstype":"btrfs", "pkname":null}
       ]
    }"#;

    /// One LV spread over two PVs; old lsblk without PATH.
    const LV_ON_TWO_PVS: &str = r#"{
       "blockdevices": [
          {"name":"vg-data", "type":"lvm", "uuid":"u", "fstype":"btrfs",
             "children": [
                {"name":"loop1", "type":"loop", "uuid":"p1", "fstype":"LVM2_member"},
                {"name":"loop2", "type":"loop", "uuid":"p2", "fstype":"LVM2_member"}
             ]
          }
       ]
    }"#;

    fn kinds(s: &BlockStack) -> Vec<LayerKind> {
        s.layers.iter().map(|l| l.kind).collect()
    }

    #[test]
    fn luks_on_partition() {
        let s = parse_lsblk(LUKS_ON_PART).unwrap();
        assert_eq!(
            kinds(&s),
            [LayerKind::Luks, LayerKind::Partition, LayerKind::Disk]
        );
        let luks = &s.layers[0];
        assert_eq!(luks.device, Path::new("/dev/mapper/luks-3f0c"));
        assert_eq!(
            luks.uuid.as_deref(),
            Some("3f0c1a2b-1111-2222-3333-444455556666")
        );
        let d = luks.detail.as_deref().unwrap();
        assert!(d.contains("cabecera LUKS en /dev/nvme0n1p2"), "{d}");
        assert!(d.contains("contiene btrfs"), "{d}");
        assert!(s.layers[1]
            .detail
            .as_deref()
            .unwrap()
            .contains("crypto_LUKS"));
        assert_eq!(s.layers[2].uuid, None);
    }

    #[test]
    fn lvm_on_luks_on_loop() {
        let s = parse_lsblk(LVM_ON_LUKS).unwrap();
        assert_eq!(
            kinds(&s),
            [LayerKind::LvmLv, LayerKind::Luks, LayerKind::Loop]
        );
        assert_eq!(
            s.layers[1].uuid.as_deref(),
            Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        );
        assert!(s.layers[0]
            .detail
            .as_deref()
            .unwrap()
            .starts_with("LV partshield--test--42--vg-lv"));
        assert_eq!(s.layers[2].device, Path::new("/dev/loop7"));
    }

    #[test]
    fn plain_loop() {
        let s = parse_lsblk(PLAIN_LOOP).unwrap();
        assert_eq!(kinds(&s), [LayerKind::Loop]);
        assert_eq!(
            s.layers[0].uuid.as_deref(),
            Some("856546ef-38b5-4081-8dbd-85ec99b72676")
        );
    }

    #[test]
    fn several_parents_and_missing_path() {
        let s = parse_lsblk(LV_ON_TWO_PVS).unwrap();
        assert_eq!(
            kinds(&s),
            [LayerKind::LvmLv, LayerKind::Loop, LayerKind::Loop]
        );
        assert_eq!(s.layers[1].device, Path::new("/dev/loop1"));
        assert!(s.layers[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("sobre loop1, loop2"));
    }

    #[test]
    fn crypt_without_header_and_unknown_types() {
        let s = parse_lsblk(
            r#"{"blockdevices":[{"name":"plain","path":"/dev/mapper/plain","type":"crypt",
                "children":[{"name":"md0","path":"/dev/md0","type":"raid1",
                  "children":[{"name":"loop0","path":"/dev/loop0","type":"loop"}]}]}]}"#,
        )
        .unwrap();
        assert_eq!(
            kinds(&s),
            [LayerKind::Luks, LayerKind::Other, LayerKind::Loop]
        );
        assert!(s.layers[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("sin cabecera LUKS"));
        assert_eq!(s.layers[1].detail.as_deref(), Some("tipo raid1"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_lsblk("no es json").is_err());
        assert!(parse_lsblk(r#"{"otra":1}"#).is_err());
    }

    #[test]
    fn blkid_fills_what_lsblk_lacks() {
        let out = "DEVNAME=/dev/loop0\nUUID=ecb5a313-ae6f-49b6-b876-c131297e3609\n\
                   UUID_SUB=e430b487-2209-47f8-aa81-44dbeaab1660\nBLOCK_SIZE=4096\nTYPE=btrfs\n";
        assert_eq!(
            parse_blkid_export(out),
            (
                Some("ecb5a313-ae6f-49b6-b876-c131297e3609".into()),
                Some("btrfs".into())
            )
        );
        assert_eq!(parse_blkid_export(""), (None, None));
    }

    // ------------------------------------------------------- cabecera LUKS

    const UUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    fn header(magic: &[u8; 6], version: u16) -> Vec<u8> {
        let mut b = vec![0u8; LUKS_READ];
        b[..6].copy_from_slice(magic);
        b[6..8].copy_from_slice(&version.to_be_bytes());
        b[LUKS_UUID_OFFSET..LUKS_UUID_OFFSET + UUID.len()].copy_from_slice(UUID.as_bytes());
        b
    }

    fn image(blocks: &[(u64, Vec<u8>)]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.as_file().set_len(8 << 20).unwrap();
        for (off, b) in blocks {
            f.seek(SeekFrom::Start(*off)).unwrap();
            f.write_all(b).unwrap();
        }
        f
    }

    #[test]
    fn parses_header_blocks() {
        assert_eq!(
            parse_luks_block(&header(LUKS_MAGIC, 1)),
            Some((true, 1, UUID.to_string()))
        );
        assert_eq!(
            parse_luks_block(&header(LUKS2_SECONDARY_MAGIC, 2)),
            Some((false, 2, UUID.to_string()))
        );
        assert_eq!(parse_luks_block(&[0u8; LUKS_READ]), None);
        assert_eq!(parse_luks_block(&LUKS_MAGIC[..]), None);
    }

    #[test]
    fn finds_luks2_primary_and_secondary() {
        let img = image(&[
            (0, header(LUKS_MAGIC, 2)),
            (0x4000, header(LUKS2_SECONDARY_MAGIC, 2)),
        ]);
        let h = luks_header(img.path()).unwrap().unwrap();
        assert_eq!(
            h,
            LuksHeader {
                version: 2,
                uuid: UUID.into(),
                primary: true,
                secondary: Some(0x4000)
            }
        );
        assert!(h.describe().contains("LUKS2"));
    }

    #[test]
    fn finds_secondary_when_primary_is_wiped() {
        let img = image(&[(0x40_0000, header(LUKS2_SECONDARY_MAGIC, 2))]);
        let h = luks_header(img.path()).unwrap().unwrap();
        assert!(!h.primary);
        assert_eq!(h.secondary, Some(0x40_0000));
        assert!(h.describe().contains("solo queda la cabecera secundaria"));
    }

    #[test]
    fn luks1_and_no_header() {
        let h = luks_header(image(&[(0, header(LUKS_MAGIC, 1))]).path())
            .unwrap()
            .unwrap();
        assert_eq!((h.version, h.primary, h.secondary), (1, true, None));
        assert_eq!(luks_header(image(&[]).path()).unwrap(), None);
    }

    // ------------------------------------------------- integración (root)

    /// LVM on LUKS on a loop device over a file in a tempdir.
    ///
    /// Runs only with `PARTSHIELD_E2E=1`, as root. Every device it creates
    /// is named `partshield-test-<pid>-…` and checked to sit on the loop it
    /// created before anything is written to it. Needs a kernel with
    /// device-mapper and dm-crypt; without them it checks the LUKS header
    /// on the loop device only, and says so.
    #[test]
    fn e2e_lvm_on_luks_on_loop() {
        if std::env::var_os("PARTSHIELD_E2E").as_deref() != Some(std::ffi::OsStr::new("1")) {
            return;
        }
        let mut t = Teardown::default();
        let res = run_lvm_on_luks(&mut t);
        t.run();
        res.unwrap();
    }

    /// Releases everything the test created, in reverse order, even after a
    /// failure (errors are only printed).
    #[derive(Default)]
    struct Teardown(Vec<Cmd>);

    impl Teardown {
        fn push(&mut self, c: Cmd) {
            self.0.push(c);
        }

        fn run(&mut self) {
            let mut s = Session::new(true);
            while let Some(c) = self.0.pop() {
                if let Err(e) = s.run(c) {
                    eprintln!("limpieza: {e:#}");
                }
            }
        }
    }

    impl Drop for Teardown {
        fn drop(&mut self) {
            self.run();
        }
    }

    fn has_device_mapper() -> bool {
        std::fs::read_to_string("/proc/misc").is_ok_and(|m| m.contains("device-mapper"))
    }

    /// Every slave of `dm` (a /dev/dm-N), recursively, must end in `lo`.
    fn assert_sits_on(dm: &Path, lo: &str) {
        let name = dm.canonicalize().unwrap();
        let name = name.file_name().unwrap().to_string_lossy().into_owned();
        let slaves: Vec<String> = std::fs::read_dir(format!("/sys/class/block/{name}/slaves"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(!slaves.is_empty(), "{name} no tiene dispositivos debajo");
        for sl in slaves {
            if sl.starts_with("dm-") {
                assert_sits_on(&Path::new("/dev").join(&sl), lo);
            } else {
                assert_eq!(format!("/dev/{sl}"), lo, "{name} cuelga de {sl}");
            }
        }
    }

    fn lvm(cmd: &str) -> Cmd {
        // No udev in test containers, and never look at devices that are
        // not ours.
        Cmd::new(cmd).arg("--config").arg(
            "devices { use_devicesfile=0 global_filter=[ \"a|^/dev/mapper/partshield-test-|\", \"r|.*|\" ] } \
             activation { udev_sync=0 udev_rules=0 }",
        )
    }

    fn run_lvm_on_luks(t: &mut Teardown) -> Result<()> {
        let mut s = Session::new(true);
        let prefix = format!("partshield-test-{}", std::process::id());
        let dir = tempfile::tempdir()?;
        let img = dir.path().join("disk.img");
        File::create(&img)?.set_len(512 << 20)?;
        let key = dir.path().join("key");
        std::fs::write(&key, b"partshield-test-key-not-secret")?;

        let lo = s
            .run(Cmd::new("losetup").arg("--find").arg("--show").arg(&img))?
            .trim()
            .to_string();
        anyhow::ensure!(lo.starts_with("/dev/loop"), "losetup devolvió {lo}");
        t.push(Cmd::new("losetup").arg("-d").arg(&lo));

        let format = s.run_unchecked(
            &Cmd::new("cryptsetup")
                .arg("luksFormat")
                .arg("--batch-mode")
                .arg("--type")
                .arg("luks2")
                .arg("--pbkdf")
                .arg("pbkdf2")
                .arg("--pbkdf-force-iterations")
                .arg("1000")
                .arg("--key-file")
                .arg(&key)
                .arg(&lo),
        )?;
        if !format.success {
            anyhow::ensure!(
                !has_device_mapper(),
                "cryptsetup luksFormat falló: {}",
                format.stderr.trim()
            );
            eprintln!(
                "AVISO: este kernel no tiene device-mapper ni AF_ALG; cryptsetup no puede \
                 formatear ({}). Se omite la prueba LUKS/LVM.",
                format.stderr.trim()
            );
            return Ok(());
        }

        // The header on the loop device, read directly.
        let header = luks_header(Path::new(&lo))?.context("no se ve la cabecera LUKS")?;
        let uuid = s
            .run(Cmd::new("cryptsetup").arg("luksUUID").arg(&lo))?
            .trim()
            .to_string();
        assert_eq!(header.version, 2);
        assert_eq!(header.uuid, uuid);
        assert!(header.primary && header.secondary.is_some(), "{header:?}");
        let stack = block_stack(&mut s, Path::new(&lo))?;
        assert_eq!(kinds(&stack), [LayerKind::Loop]);
        let d = stack.layers[0].detail.as_deref().unwrap_or("");
        assert!(d.contains("contiene crypto_LUKS"), "{stack:?}");
        assert!(d.contains("cabecera LUKS2"), "{stack:?}");
        assert_eq!(stack.layers[0].uuid.as_deref(), Some(uuid.as_str()));

        if !has_device_mapper() {
            eprintln!(
                "AVISO: el kernel no tiene device-mapper; solo se ha comprobado la cabecera LUKS \
                 sobre {lo}. LvmLv → Luks → Loop queda sin probar aquí."
            );
            return Ok(());
        }
        anyhow::ensure!(
            !crate::cmd::sandboxed(),
            "con PARTSHIELD_SANDBOX=1 no se permite /dev/mapper (pendiente del lead); \
             ejecuta esta prueba sin el sandbox"
        );

        let crypt = format!("{prefix}-crypt");
        s.run(
            Cmd::new("cryptsetup")
                .arg("open")
                .arg("--key-file")
                .arg(&key)
                .arg(&lo)
                .arg(&crypt),
        )?;
        t.push(Cmd::new("cryptsetup").arg("close").arg(&crypt));
        let crypt_dev = PathBuf::from(format!("/dev/mapper/{crypt}"));
        assert_sits_on(&crypt_dev, &lo);

        let vg = format!("{prefix}-vg");
        s.run(lvm("pvcreate").arg("-q").arg(&crypt_dev))?;
        t.push(lvm("pvremove").arg("-ff").arg("-y").arg(&crypt_dev));
        s.run(lvm("vgcreate").arg("-q").arg(&vg).arg(&crypt_dev))?;
        t.push(lvm("vgremove").arg("-f").arg(&vg));
        s.run(
            lvm("lvcreate")
                .arg("-q")
                .arg("-y")
                .arg("-n")
                .arg("lv")
                .arg("-L")
                .arg("300M")
                .arg("-Z")
                .arg("n")
                .arg(&vg),
        )?;
        t.push(lvm("lvchange").arg("-an").arg(format!("{vg}/lv")));
        // dm names double the dashes inside VG/LV names.
        let lv_dev = PathBuf::from(format!("/dev/mapper/{}-lv", vg.replace('-', "--")));
        assert_sits_on(&lv_dev, &lo);

        s.run(Cmd::new("mkfs.btrfs").arg("-q").arg("-f").arg(&lv_dev))?;
        let stack = block_stack(&mut s, &lv_dev)?;
        assert_eq!(
            kinds(&stack),
            [LayerKind::LvmLv, LayerKind::Luks, LayerKind::Loop],
            "{stack:?}"
        );
        assert_eq!(stack.layers[1].uuid.as_deref(), Some(uuid.as_str()));
        assert_eq!(stack.layers[2].device, Path::new(&lo));
        assert!(stack.layers[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("contiene btrfs"));
        Ok(())
    }
}
