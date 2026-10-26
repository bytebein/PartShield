//! Listado de discos y particiones para la interfaz (`lsblk -J -b`).
//! Solo lee: no abre ningún dispositivo.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

use crate::cmd::{Cmd, Session};

/// Un disco (o loop) con lo que contiene, aplanado en orden de árbol.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Disk {
    pub path: PathBuf,
    pub kind: String,
    pub size: u64,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub transport: Option<String>,
    pub removable: bool,
    pub volumes: Vec<Volume>,
}

/// Partición, LUKS abierto, volumen lógico… o el propio disco si tiene un
/// sistema de archivos sin tabla de particiones.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Volume {
    pub path: PathBuf,
    pub kind: String,
    /// 0 = directamente en el disco; más = dentro de otra capa (LUKS, LVM).
    pub depth: usize,
    pub size: u64,
    pub fstype: Option<String>,
    pub label: Option<String>,
    pub uuid: Option<String>,
    pub mountpoints: Vec<String>,
}

impl Volume {
    pub fn is_btrfs(&self) -> bool {
        self.fstype.as_deref() == Some("btrfs")
    }

    /// El USB desde el que arrancó la ISO.
    pub fn is_live_medium(&self) -> bool {
        self.mountpoints
            .iter()
            .any(|m| m == "/run/live/medium" || m == "/lib/live/mount/medium")
    }
}

pub const LSBLK_COLUMNS: &str =
    "NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,UUID,MODEL,SERIAL,TRAN,RM,MOUNTPOINTS";

pub fn list(s: &mut Session) -> Result<Vec<Disk>> {
    let out = s.run(
        Cmd::new("lsblk")
            .arg("-J")
            .arg("-b")
            .arg("-o")
            .arg(LSBLK_COLUMNS),
    )?;
    parse(&out)
}

/// Discos de `lsblk -J -b -o LSBLK_COLUMNS`. Omite zram, cdrom vacíos y
/// loops sin archivo detrás.
pub fn parse(json: &str) -> Result<Vec<Disk>> {
    let v: Value = serde_json::from_str(json).context("salida de lsblk no válida")?;
    let mut disks = Vec::new();
    for d in v["blockdevices"].as_array().into_iter().flatten() {
        let kind = text(d, "type").unwrap_or_default();
        let size = number(d, "size");
        let name = text(d, "name").unwrap_or_default();
        if name.starts_with("zram") || size == 0 || !matches!(kind.as_str(), "disk" | "loop" | "rom") {
            continue;
        }
        let mut volumes = Vec::new();
        // Un disco formateado entero (sin particiones) también es un volumen.
        if text(d, "fstype").is_some() {
            volumes.push(volume(d, 0));
        }
        collect(d, 0, &mut volumes);
        disks.push(Disk {
            path: path_of(d),
            kind,
            size,
            model: text(d, "model"),
            serial: text(d, "serial"),
            transport: text(d, "tran"),
            removable: flag(d, "rm"),
            volumes,
        });
    }
    Ok(disks)
}

fn collect(node: &Value, depth: usize, out: &mut Vec<Volume>) {
    for c in node["children"].as_array().into_iter().flatten() {
        out.push(volume(c, depth));
        collect(c, depth + 1, out);
    }
}

fn volume(v: &Value, depth: usize) -> Volume {
    Volume {
        path: path_of(v),
        kind: text(v, "type").unwrap_or_default(),
        depth,
        size: number(v, "size"),
        fstype: text(v, "fstype"),
        label: text(v, "label"),
        uuid: text(v, "uuid"),
        mountpoints: v["mountpoints"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|m| m.as_str().map(str::to_string))
            .collect(),
    }
}

fn path_of(v: &Value) -> PathBuf {
    text(v, "path")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/dev/{}", text(v, "name").unwrap_or_default())))
}

fn text(v: &Value, key: &str) -> Option<String> {
    v[key]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// lsblk escribe los números como número o como texto según la versión.
fn number(v: &Value, key: &str) -> u64 {
    v[key]
        .as_u64()
        .or_else(|| v[key].as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0)
}

fn flag(v: &Value, key: &str) -> bool {
    v[key].as_bool().unwrap_or_else(|| v[key].as_str() == Some("1") || v[key].as_u64() == Some(1))
}

/// 512110190592 → "477 GiB".
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 || v >= 100.0 {
        format!("{v:.0} {}", UNITS[i])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Portátil con NVMe (EFI + Btrfs en LUKS), NVMe extra vacío, USB de
    /// arranque de la ISO, zram y un loop sin archivo.
    const SAMPLE: &str = r#"{"blockdevices":[
      {"name":"nvme0n1","path":"/dev/nvme0n1","type":"disk","size":1024209543168,"fstype":null,"label":null,"uuid":null,"model":"Samsung SSD 980 PRO 1TB","serial":"S5GXNF0R1","tran":"nvme","rm":false,"mountpoints":[null],
        "children":[
          {"name":"nvme0n1p1","path":"/dev/nvme0n1p1","type":"part","size":1073741824,"fstype":"vfat","label":null,"uuid":"A1B2-C3D4","model":null,"serial":null,"tran":"nvme","rm":false,"mountpoints":[null]},
          {"name":"nvme0n1p2","path":"/dev/nvme0n1p2","type":"part","size":1023134760960,"fstype":"crypto_LUKS","label":null,"uuid":"c0ffee","model":null,"serial":null,"tran":"nvme","rm":false,"mountpoints":[null],
            "children":[{"name":"luks-c0ffee","path":"/dev/mapper/luks-c0ffee","type":"crypt","size":1023118000000,"fstype":"btrfs","label":"cachyos","uuid":"b7f1","model":null,"serial":null,"tran":null,"rm":false,"mountpoints":[null]}]}
        ]},
      {"name":"nvme1n1","path":"/dev/nvme1n1","type":"disk","size":"2000398934016","fstype":null,"label":null,"uuid":null,"model":"WD_BLACK SN850X 2000GB ","serial":"23XYZ","tran":"nvme","rm":"0","mountpoints":[null]},
      {"name":"sda","path":"/dev/sda","type":"disk","size":31029460992,"fstype":"iso9660","label":"PARTSHIELD","uuid":null,"model":"Ultra Fit","serial":"4C53","tran":"usb","rm":true,"mountpoints":["/run/live/medium"]},
      {"name":"zram0","path":"/dev/zram0","type":"disk","size":8589934592,"fstype":"swap","label":null,"uuid":null,"model":null,"serial":null,"tran":null,"rm":false,"mountpoints":["[SWAP]"]},
      {"name":"loop7","path":"/dev/loop7","type":"loop","size":0,"fstype":null,"label":null,"uuid":null,"model":null,"serial":null,"tran":null,"rm":false,"mountpoints":[null]}
    ]}"#;

    #[test]
    fn parses_disks_layers_and_live_medium() {
        let disks = parse(SAMPLE).unwrap();
        let names: Vec<_> = disks.iter().map(|d| d.path.display().to_string()).collect();
        assert_eq!(names, ["/dev/nvme0n1", "/dev/nvme1n1", "/dev/sda"]);

        let main = &disks[0];
        assert_eq!(main.model.as_deref(), Some("Samsung SSD 980 PRO 1TB"));
        assert_eq!(main.volumes.len(), 3);
        let btrfs = &main.volumes[2];
        assert!(btrfs.is_btrfs());
        assert_eq!(btrfs.depth, 1, "Btrfs dentro de LUKS");
        assert_eq!(btrfs.path, PathBuf::from("/dev/mapper/luks-c0ffee"));
        assert_eq!(btrfs.label.as_deref(), Some("cachyos"));

        let extra = &disks[1];
        assert_eq!(extra.size, 2_000_398_934_016, "tamaño como texto");
        assert_eq!(extra.model.as_deref(), Some("WD_BLACK SN850X 2000GB"));
        assert!(extra.volumes.is_empty());
        assert!(!extra.removable);

        let usb = &disks[2];
        assert!(usb.removable);
        assert!(usb.volumes[0].is_live_medium(), "ISO formateada en todo el disco");
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(1_024_209_543_168), "954 GiB");
        assert_eq!(human_size(2_000_398_934_016), "1.8 TiB");
    }
}
