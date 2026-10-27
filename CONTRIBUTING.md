# Contribuir a PartShield

PartShield escribe en discos. Por eso estas reglas no son opcionales.

## Solo loop devices

- **Nunca** pruebes sobre `/dev/nvme*`, `/dev/sd*` ni ningún disco real.
- Usa loop devices sobre archivos dentro de un directorio temporal.
- Exporta siempre `PARTSHIELD_SANDBOX=1`. Con él, PartShield rechaza cualquier
  comando que nombre un `/dev/` que no sea `/dev/loop*`, también a través de
  enlaces simbólicos. El código que abre un dispositivo directamente pasa por
  `cmd::guard_path`, que hace la misma comprobación.
- Antes de soltar un loop device, desmóntalo. Libera siempre lo que crees,
  también si el test falla.

## «Hecho» significa

1. `cargo fmt --check`, `cargo clippy --workspace --all-targets` sin avisos y
   `cargo test --workspace` en verde.
2. Las pruebas de punta a punta, con root y loop devices:

   ```sh
   sudo PARTSHIELD_SANDBOX=1 PARTSHIELD_E2E=1 cargo test --test e2e --test raw_e2e --test multi_e2e
   sudo PARTSHIELD_SANDBOX=1 PARTSHIELD_GUI_E2E=1 cargo test -p partshield-gui
   ```

   La primera es la puerta original del proyecto: restaurar y montar una
   copia de un Btrfs con `BLOCK_GROUP_TREE`.
3. Para la ISO: `iso/scripts/build-iso.sh` y sus pruebas de arranque en QEMU
   (BIOS, UEFI y Secure Boot).

Que compile no es «hecho». Que funcione en QEMU tampoco es «funciona en
hardware real»: dilo tal cual en el PR.

## Cómo está organizado

| Módulo | Contenido |
| --- | --- |
| `crates/core/src/types.rs`, `cmd.rs`, `lib.rs` | Tipos compartidos, ejecución de comandos y orquestación |
| `crates/core/src/detect/` | Superbloque, features por modo, LUKS/LVM, discos |
| `crates/core/src/send/` | Snapshots, send/receive, zstd, incrementales, restauración, tabla de particiones, ESP y UUID |
| `crates/core/src/raw/` | Imagen sector a sector y su verificación |
| `crates/core/src/verify/` | Restauración de prueba y los cinco pasos |
| `crates/core/src/report/` | Informe JSON y HTML, firma ed25519 |
| `crates/cli` | Línea de órdenes |
| `crates/gui` | Interfaz GTK 4 + libadwaita (modo sencillo en `basic.rs`) |
| `iso` | Live USB con live-build (Debian 13, Secure Boot) |

Un cambio en los tipos compartidos (`types.rs`, `cmd.rs`) afecta a todo:
explícalo en el PR.

## Estilo

- Código, comentarios, mensajes de la interfaz y commits en español.
- Cada comando externo pasa por `Session`, que lo muestra y lo guarda en el
  informe: nada de `std::process::Command` suelto en el motor.
- Una copia solo es **válida** si pasan los cinco pasos. No añadas atajos que
  den por buena una copia sin restaurarla.

## Licencia

Al contribuir aceptas que tu código se publique bajo la
[GPL-3.0 o posterior](LICENSE).
