use super::*;
use crate::send::testutil::{e2e_enabled, image, run, Cleanup};

const SFDISK_JSON: &str = r#"{
   "partitiontable": {
      "label": "gpt",
      "id": "F8AA0764-8EAC-42FE-A501-C24BB65B2C82",
      "device": "/dev/loop0",
      "unit": "sectors",
      "firstlba": 34,
      "lastlba": 409566,
      "sectorsize": 512,
      "partitions": [
         {"node": "/dev/loop0p1", "start": 2048, "size": 81920,
          "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "uuid": "2798DB0F-2707-45F4-B947-2EC8BD5491AC"},
         {"node": "/dev/loop0p2", "start": 83968, "size": 325599,
          "type": "0FC63DAF-8483-4772-8E79-3D69D8477DE4", "uuid": "55864E8B-8FA4-4FFD-8248-9E65CF16E138"}
      ]
   }
}"#;

#[test]
fn parses_sfdisk_and_finds_esp() {
    let t = PartTable::parse(SFDISK_JSON).unwrap();
    assert_eq!(t.label, "gpt");
    assert_eq!(t.partitions.len(), 2);
    let (p, off, len) = t.esp().unwrap();
    assert_eq!(p.node, "/dev/loop0p1");
    assert_eq!((off, len), (2048 * 512, 81920 * 512));

    let mbr = r#"{"partitiontable":{"label":"dos","partitions":[
        {"node":"/dev/sda1","start":2048,"size":100,"type":"83"},
        {"node":"/dev/sda2","start":4096,"size":200,"type":"ef"}]}}"#;
    let t = PartTable::parse(mbr).unwrap();
    assert_eq!(t.sectorsize, 512);
    assert_eq!(t.esp().unwrap().0.node, "/dev/sda2");

    let none = r#"{"partitiontable":{"label":"gpt","partitions":[]}}"#;
    assert!(PartTable::parse(none).unwrap().esp().is_none());
}

#[test]
fn parses_blkid_export() {
    let out = "DEVNAME=/dev/loop1\nUUID=ee02aee3-017f\nUUID_SUB=x\nBLOCK_SIZE=4096\nTYPE=btrfs\n";
    assert_eq!(
        parse_blkid(out),
        (Some("btrfs".into()), Some("ee02aee3-017f".into()))
    );
    assert_eq!(parse_blkid(""), (None, None));
}

#[test]
fn finds_parent_disk() {
    assert_eq!(
        parse_parent_disk("/dev/loop0p2 part\n/dev/loop0 loop\n"),
        Some(PathBuf::from("/dev/loop0"))
    );
    assert_eq!(
        parse_parent_disk("/dev/mapper/root crypt\n/dev/nvme0n1p2 part\n/dev/nvme0n1 disk\n"),
        Some(PathBuf::from("/dev/nvme0n1"))
    );
    assert_eq!(parse_parent_disk("/dev/loop3 loop\n"), None);
}

#[test]
fn spots_mounted_partitions() {
    assert!(is_disk_or_partition("/dev/loop1", "/dev/loop1"));
    assert!(is_disk_or_partition("/dev/loop1p2", "/dev/loop1"));
    assert!(!is_disk_or_partition("/dev/loop10", "/dev/loop1"));
    assert!(is_disk_or_partition("/dev/sda1", "/dev/sda"));
    assert!(!is_disk_or_partition("/dev/sdab", "/dev/sda"));
    let findmnt = "/dev/vda\n/dev/loop10[/@]\n/dev/loop1p2[/@home]\n";
    assert_eq!(
        mounted_sources_touch(findmnt, "/dev/loop1").as_deref(),
        Some("/dev/loop1p2")
    );
    assert_eq!(mounted_sources_touch(findmnt, "/dev/loop2"), None);
}

#[test]
fn dd_commands_stay_inside_the_partition() {
    let r = dd_read(Path::new("/dev/loop0"), 1048576, 4096).to_string();
    assert_eq!(
        r,
        "dd if=/dev/loop0 bs=1M iflag=skip_bytes,count_bytes skip=1048576 count=4096 status=none"
    );
    let w = dd_write(Path::new("/dev/loop0"), 1048576, 4096).to_string();
    assert!(w.contains("of=/dev/loop0") && w.contains("seek=1048576") && w.contains("count=4096"));
    assert!(w.contains("conv=notrunc,fsync"));
}

#[test]
fn counting_refuses_overflow() {
    let mut c = Counting {
        hasher: Hasher::new(HashAlgo::Blake3),
        bytes: 0,
        cap: 4,
    };
    c.write_all(b"abcd").unwrap();
    assert!(c.write_all(b"e").is_err());
}

/// Un archivo dañado para la restauración antes de escribir nada.
#[test]
fn restore_checks_hashes_before_writing() {
    let dir = tempfile::tempdir().unwrap();
    let table = dir.path().join("x.gpt");
    std::fs::write(&table, b"tabla").unwrap();
    let digest = Digest::of_file(HashAlgo::Blake3, &table).unwrap();
    std::fs::write(&table, b"tablA").unwrap();
    let layout = DiskLayout {
        partition_table: Some(StreamRef {
            digest: Some(digest),
            ..StreamRef::plain(table)
        }),
        ..DiskLayout::default()
    };
    let target = dir.path().join("destino.img");
    image(&target, 1 << 20);
    let mut s = Session::new(false);
    let err = restore_layout(
        &mut s,
        &LayoutRestoreOptions {
            layout: &layout,
            target_disk: &target,
            btrfs_device: None,
        },
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("dañado"), "{err:#}");
    assert!(s.records.is_empty());
}

#[test]
fn capture_refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("x.gpt"), "").unwrap();
    let mut s = Session::new(false);
    let err = capture(&mut s, Path::new("/nada"), dir.path(), "x").unwrap_err();
    assert!(err.to_string().contains("ya existe"));
    assert!(s.records.is_empty());
}

// ------------------------------------------------- disco de prueba

const MIB: u64 = 1 << 20;
const DISK_BYTES: u64 = 320 * MIB;
const EFI_FILE: &[u8] = b"cargador de arranque de prueba\n";

fn have(tools: &[&str]) -> bool {
    let mut s = Session::new(false);
    let missing: Vec<_> = tools
        .iter()
        .filter(|t| {
            s.run_unchecked(&Cmd::new("sh").arg("-c").arg(format!("command -v {t}")))
                .map_or(true, |o| !o.success)
        })
        .collect();
    if !missing.is_empty() {
        eprintln!("faltan {missing:?}: prueba omitida");
    }
    missing.is_empty()
}

/// GPT con una ESP de 64 MiB y una partición Linux con el resto.
fn partition(s: &mut Session, img: &Path) {
    image(img, DISK_BYTES);
    run(
        s,
        Cmd::new("sgdisk")
            .arg("-n1:0:+64M")
            .arg("-t1:EF00")
            .arg("-c1:EFI")
            .arg("-n2:0:0")
            .arg("-t2:8300")
            .arg("-c2:raiz")
            .arg(img),
    );
}

fn make_esp(s: &mut Session, dev: &Path, scratch: &Path) {
    run(
        s,
        Cmd::new("mkfs.vfat")
            .arg("-F")
            .arg("32")
            .arg("-s")
            .arg("1")
            .arg("-n")
            .arg("PSHIELD")
            .arg(dev),
    );
    let src = scratch.join("BOOTX64.EFI");
    std::fs::write(&src, EFI_FILE).unwrap();
    let img = dev.to_string_lossy().into_owned();
    run(
        s,
        Cmd::new("mmd")
            .arg("-i")
            .arg(&img)
            .arg("::/EFI")
            .arg("::/EFI/BOOT"),
    );
    run(
        s,
        Cmd::new("mcopy")
            .arg("-i")
            .arg(&img)
            .arg(&src)
            .arg("::/EFI/BOOT/BOOTX64.EFI"),
    );
}

fn efi_file(s: &mut Session, dev: &Path) -> String {
    run(
        s,
        Cmd::new("mtype")
            .arg("-i")
            .arg(dev)
            .arg("::/EFI/BOOT/BOOTX64.EFI"),
    )
}

fn mkfs_btrfs(s: &mut Session, dev: &Path) {
    run(
        s,
        Cmd::new("mkfs.btrfs")
            .arg("-q")
            .arg("-f")
            .arg("-O")
            .arg("block-group-tree")
            .arg(dev),
    );
}

fn blkid_uuid(s: &mut Session, dev: &Path) -> Option<String> {
    probe(s, dev).unwrap().1
}

/// `sgdisk -p` sin la primera línea, que nombra el dispositivo.
fn table_text(s: &mut Session, img: &Path) -> String {
    let out = run(s, Cmd::new("sgdisk").arg("-p").arg(img));
    out.lines().skip(1).collect::<Vec<_>>().join("\n")
}

fn region(img: &Path, offset: u64, len: u64) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = File::open(img).unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    let mut v = vec![0; len as usize];
    f.read_exact(&mut v).unwrap();
    v
}

fn esp_range(s: &mut Session, img: &Path) -> (u64, u64) {
    let t = read_table(s, img).unwrap();
    let (_, off, len) = t.esp().unwrap();
    (off, len)
}

/// Sin root: el disco, la ESP y el Btrfs son archivos de imagen.
#[test]
fn layout_roundtrip_on_image_files() {
    if !have(&[
        "sgdisk",
        "sfdisk",
        "mkfs.vfat",
        "mmd",
        "mcopy",
        "mkfs.btrfs",
        "btrfstune",
        "blkid",
    ]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let mut s = Session::new(false);

    let disk_a = d.join("a.img");
    partition(&mut s, &disk_a);
    let (off, len) = esp_range(&mut s, &disk_a);
    let esp_a = d.join("esp-a.img");
    image(&esp_a, len);
    make_esp(&mut s, &esp_a, d);
    run(
        &mut s,
        Cmd::new("dd")
            .arg(format!("if={}", esp_a.display()))
            .arg(format!("of={}", disk_a.display()))
            .arg("bs=1M")
            .arg("oflag=seek_bytes")
            .arg(format!("seek={off}"))
            .arg("conv=notrunc")
            .arg("status=none"),
    );
    let fs_a = d.join("fs-a.img");
    image(&fs_a, 256 * MIB);
    mkfs_btrfs(&mut s, &fs_a);

    let dest = d.join("copias");
    let layout = capture_with(
        &mut s,
        &CaptureOptions {
            fs_device: &fs_a,
            disk: Some(&disk_a),
            dest_dir: &dest,
            name: "sis",
            zstd_level: 3,
            hash: HashAlgo::Sha256,
        },
    )
    .unwrap();
    assert_eq!(layout.fs_uuid, blkid_uuid(&mut s, &fs_a));
    assert!(layout.partition_table.is_some() && layout.esp.is_some());
    assert!(dest.join("sis.sfdisk.txt").exists());
    assert!(!dest.join("sis.esp.img.zst.partial").exists());

    let disk_b = d.join("b.img");
    image(&disk_b, DISK_BYTES);
    let fs_b = d.join("fs-b.img");
    image(&fs_b, 256 * MIB);
    mkfs_btrfs(&mut s, &fs_b);
    let done = restore_layout(
        &mut s,
        &LayoutRestoreOptions {
            layout: &layout,
            target_disk: &disk_b,
            btrfs_device: Some(&fs_b),
        },
    )
    .unwrap();
    assert!(done.partition_table);
    assert_eq!(done.esp, Some((off, len)));

    assert_eq!(table_text(&mut s, &disk_a), table_text(&mut s, &disk_b));
    assert!(region(&disk_a, off, len) == region(&disk_b, off, len));
    assert_eq!(blkid_uuid(&mut s, &fs_b), layout.fs_uuid);
}

/// Con root y loop devices: `PARTSHIELD_SANDBOX=1 PARTSHIELD_E2E=1`.
///
/// Si el kernel no lee tablas GPT (sin `CONFIG_EFI_PARTITION`, como en
/// algunas VM), `losetup -P` no crea `/dev/loopNpM`; entonces cada partición
/// se conecta a su propio loop device con `--offset`/`--sizelimit`.
#[test]
fn e2e_layout_capture_and_restore_on_loop_devices() {
    if !e2e_enabled() || !have(&["sgdisk", "sfdisk", "mkfs.vfat", "mmd", "mcopy", "mtype"]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let mut s = Session::new(false);
    let mut c = Cleanup::default();

    let img_a = d.join("disco-a.img");
    partition(&mut s, &img_a);
    let (disk_a, parts_a) = attach_disk(&mut s, &mut c, &img_a);
    let (esp_a, root_a) = (parts_a[0].clone(), parts_a[1].clone());
    make_esp(&mut s, Path::new(&esp_a), d);
    mkfs_btrfs(&mut s, Path::new(&root_a));
    let uuid_a = blkid_uuid(&mut s, Path::new(&root_a)).unwrap();

    let dest = d.join("copias");
    let layout = capture_with(
        &mut s,
        &CaptureOptions {
            fs_device: Path::new(&root_a),
            // Con nodos de partición reales, lsblk encuentra el disco solo.
            disk: (!is_node(&root_a, &disk_a)).then_some(Path::new(&disk_a)),
            dest_dir: &dest,
            name: "sistema",
            zstd_level: 3,
            hash: HashAlgo::Blake3,
        },
    )
    .unwrap();
    assert_eq!(layout.fs_uuid.as_deref(), Some(uuid_a.as_str()));
    assert!(layout.partition_table.is_some());
    assert!(layout.esp.is_some(), "{:?}", layout.notes);

    // El disco original desaparece (como si se hubiera roto): así el UUID
    // no está repetido cuando se aplica al disco nuevo.
    for p in parts_a.iter().filter(|p| !is_node(p, &disk_a)) {
        c.detach(&mut s, p);
    }
    c.detach(&mut s, &disk_a);

    let img_b = d.join("disco-b.img");
    image(&img_b, DISK_BYTES);
    let disk_b = c.attach_partscan(&mut s, &img_b);
    let done = restore_layout(
        &mut s,
        &LayoutRestoreOptions {
            layout: &layout,
            target_disk: Path::new(&disk_b),
            btrfs_device: None,
        },
    )
    .unwrap();
    assert!(done.partition_table && done.esp.is_some());

    let parts_b = partitions(&mut s, &mut c, &img_b, &disk_b);
    let root_b = Path::new(&parts_b[1]);
    mkfs_btrfs(&mut s, root_b);
    assert_ne!(blkid_uuid(&mut s, root_b).as_deref(), Some(uuid_a.as_str()));
    apply_fs_uuid(&mut s, &uuid_a, root_b).unwrap();
    assert_eq!(blkid_uuid(&mut s, root_b).as_deref(), Some(uuid_a.as_str()));

    assert_eq!(table_text(&mut s, &img_a), table_text(&mut s, &img_b));
    let (off, len) = esp_range(&mut s, &img_a);
    assert!(region(&img_a, off, len) == region(&img_b, off, len));
    assert_eq!(
        efi_file(&mut s, Path::new(&parts_b[0])),
        String::from_utf8_lossy(EFI_FILE).trim()
    );
}

/// `part` es un nodo de partición del kernel (`/dev/loopNpM`) de `disk`.
fn is_node(part: &str, disk: &str) -> bool {
    part.starts_with(&format!("{disk}p"))
}

fn attach_disk(s: &mut Session, c: &mut Cleanup, img: &Path) -> (String, Vec<String>) {
    let disk = c.attach_partscan(s, img);
    let parts = partitions(s, c, img, &disk);
    (disk, parts)
}

/// `/dev/loopNp1`, `/dev/loopNp2` si el kernel los creó; si no, un loop
/// device por partición sobre el trozo de la imagen.
fn partitions(s: &mut Session, c: &mut Cleanup, img: &Path, disk: &str) -> Vec<String> {
    let _ = s.run(Cmd::new("partx").arg("-u").arg(disk));
    let table = read_table(s, img).unwrap();
    let nodes: Vec<String> = (1..=table.partitions.len())
        .map(|i| format!("{disk}p{i}"))
        .collect();
    if nodes.iter().all(|n| Path::new(n).exists()) {
        return nodes;
    }
    eprintln!(
        "el kernel no creó {}: se usan loop devices con offset",
        nodes[0]
    );
    table
        .partitions
        .iter()
        .map(|p| {
            c.attach(
                s,
                img,
                Some((p.start * table.sectorsize, p.size * table.sectorsize)),
            )
        })
        .collect()
}
