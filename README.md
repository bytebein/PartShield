# PartShield

[partshield.io](https://partshield.io) · [partshield.dev](https://partshield.dev)

Copias de Btrfs que no se dan por buenas hasta que se han restaurado y comprobado.

Nace del fallo de partclone con `BLOCK_GROUP_TREE`
([partclone#303](https://github.com/Thomas-Tsai/partclone/issues/303),
[rescuezilla#672](https://github.com/rescuezilla/rescuezilla/issues/672)): tres copias
marcadas como correctas que no montaban porque el `chunk_root` nunca se copió.

Esto es la **Fase 0**: el motor en Rust y una CLI. La interfaz gráfica y el live USB
(Debian 13 *trixie*, la estable actual, con Secure Boot) vienen después y usan este mismo motor.

## Qué hace

- **`inspect`**: lee el superbloque directamente del disco (comprobando su crc32c),
  lista las features y dice qué modos de copia son seguros. partclone se bloquea si
  es anterior a 0.3.50 o si hay alguna feature que no está en la lista probada.
- **`backup`**: snapshot de solo lectura → `btrfs send` comprimido con zstd → verificación.
  Con `--parent <informe>` la copia es incremental (`btrfs send -p`) sobre una copia
  anterior **válida** cuyo snapshot se conservó (`--keep-snapshot`).
- **`backup --mode raw`**: imagen sector a sector del dispositivo entero, al estilo de
  `dd`, comprimida con zstd. Sirve para lo que no sea Btrfs o tenga features no
  probadas. Se niega si el origen está montado en lectura-escritura. Su verificación
  exige que los bytes restaurados den el mismo hash que el dispositivo, monta la copia,
  pasa `btrfs check` si es Btrfs y relee 64 trozos del origen para detectar cambios.
  `restore` la escribe en un dispositivo igual o mayor, o en un archivo nuevo disperso.
- **`restore`**: restaura la cadena (completa + incrementales) en un Btrfs montado y,
  con `--as`, deja un subvolumen escribible. Comprueba el BLAKE3 de cada stream
  **antes** de recibirlo: un archivo dañado no llega a aplicarse a medias.
- **`verify`**: restaura la cadena en un Btrfs temporal (archivo sparse + loop) y pasa
  cinco pasos:

| Paso | Qué comprueba |
| --- | --- |
| integridad | BLAKE3 del archivo comprimido igual al de la copia |
| restaurar | `btrfs receive` termina sin error |
| subvolumen | El subvolumen restaurado es de solo lectura y tiene Received UUID |
| contenido | Mismo árbol que el origen: tipos, tamaños, permisos, propietarios, enlaces y BLAKE3 de cada archivo |
| estructura | `btrfs check --readonly` sobre el sistema de archivos temporal |

El resultado es **válida** solo si pasan los cinco. Con algún paso omitido es
**reducida** (código de salida 2, salvo `--accept-reduced`) y con cualquier fallo, **no válida**.

Cada comando externo se muestra antes de ejecutarse y queda registrado en el informe
JSON que se guarda junto a la copia. El informe guarda también la cadena de streams con
sus hashes, nunca se sobrescribe, y si el disco de copias se monta en otra ruta los
streams se buscan junto al informe.

## Uso

Necesita root, `btrfs-progs`, `util-linux` (losetup, mount, findmnt) y loop devices.

```sh
cargo build --release
sudo target/release/partshield inspect /dev/nvme0n1p2

# Copia completa conservando el snapshot, y después incrementales sobre ella
sudo target/release/partshield backup /home --dest /mnt/usb/copias --keep-snapshot
sudo target/release/partshield backup /home --dest /mnt/usb/copias --keep-snapshot \
    --parent /mnt/usb/copias/home-AAAAMMDD-HHMMSS.report.json

# Volver a verificar una copia (compara con su snapshot si sigue existiendo)
sudo target/release/partshield verify --report /mnt/usb/copias/home-XXXX.report.json

# Restaurar en otro Btrfs y dejar /mnt/nuevo/home escribible
sudo target/release/partshield restore --report /mnt/usb/copias/home-XXXX.report.json \
    --to /mnt/nuevo --as home

# Imagen sector a sector de una partición desmontada (o montada en solo lectura)
sudo target/release/partshield backup --mode raw /dev/sdb2 --dest /mnt/usb/copias
sudo target/release/partshield restore --report /mnt/usb/copias/sdb2-XXXX.report.json --to /dev/sdc2
```

## Tests

```sh
cargo test                                  # unitarios
sudo PARTSHIELD_SANDBOX=1 PARTSHIELD_E2E=1 cargo test --test e2e     # puerta de la Fase 0
sudo PARTSHIELD_SANDBOX=1 PARTSHIELD_E2E=1 cargo test --test raw_e2e # modo raw
```

El test de punta a punta crea un Btrfs con `block-group-tree` y comprueba:

- una copia completa válida y que la verificación detecta un origen cambiado, un byte
  alterado, un stream cortado y la falta de referencia;
- una incremental que solo lleva los cambios y verifica la cadena entera;
- que restaurar la cadena en otro Btrfs devuelve exactamente el origen actual;
- que un stream dañado se rechaza antes de recibir nada;
- que no se encadena una incremental sobre una copia no válida.

## Pendiente

- Varios subvolúmenes y tabla de particiones/ESP en una sola copia
- Modo partclone
- Informe HTML firmado con ed25519
- Interfaz gráfica (gtk4-rs + libadwaita)
- Live USB con live-build sobre Debian 13 *trixie* (la estable actual): Secure Boot con shim-signed y el kernel
  firmado de Debian, btrfs-progs y partclone compilados y fijados, y arranque probado
  en QEMU con BIOS, UEFI y Secure Boot
