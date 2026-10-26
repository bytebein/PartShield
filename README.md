# PartShield

[partshield.io](https://partshield.io)

Copias de Btrfs que no se dan por buenas hasta que se han restaurado y comprobado.

Nace del fallo de partclone con `BLOCK_GROUP_TREE`
([partclone#303](https://github.com/Thomas-Tsai/partclone/issues/303),
[rescuezilla#672](https://github.com/rescuezilla/rescuezilla/issues/672)): tres copias
marcadas como correctas que no montaban porque el `chunk_root` nunca se copió.

Esto es la **Fase 0**: el motor en Rust y una CLI. La interfaz gráfica y el live USB
(Arch) vienen después y usan este mismo motor.

## Qué hace

- **`inspect`**: lee el superbloque directamente del disco (comprobando su crc32c),
  lista las features y dice qué modos de copia son seguros. partclone se bloquea si
  es anterior a 0.3.50 o si hay alguna feature que no está en la lista probada.
- **`backup`**: snapshot de solo lectura → `btrfs send` comprimido con zstd → verificación.
- **`verify`**: restaura un stream en un Btrfs temporal (archivo sparse + loop) y pasa
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
JSON que se guarda junto a la copia.

## Uso

Necesita root, `btrfs-progs`, `util-linux` (losetup, mount, findmnt) y loop devices.

```sh
cargo build --release
sudo target/release/partshield inspect /dev/nvme0n1p2
sudo target/release/partshield backup /home --dest /mnt/usb/copias
sudo target/release/partshield verify /mnt/usb/copias/home-*.btrfs.zst --against /ruta/original
```

Restaurar a mano mientras no exista el comando `restore`:

```sh
zstd -dc home-XXXX.btrfs.zst | sudo btrfs receive /mnt/destino
```

## Tests

```sh
cargo test                                  # unitarios
sudo PARTSHIELD_E2E=1 cargo test --test e2e # Btrfs real con BLOCK_GROUP_TREE en loop
```

El test de punta a punta crea un Btrfs con `block-group-tree`, hace una copia y
comprueba que la verificación detecta: un origen cambiado, un byte alterado en el
stream, un stream cortado y una verificación sin referencia.

## Pendiente

- `restore` y copias incrementales (`btrfs send -p`)
- Varios subvolúmenes y tabla de particiones/ESP en una sola copia
- Modos partclone y sector a sector
- Informe HTML firmado con ed25519
- Interfaz gráfica (gtk4-rs + libadwaita) y live USB con archiso
