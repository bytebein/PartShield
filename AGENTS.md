# Equipo de la Fase 0 (motor Btrfs)

La GUI y la ISO esperan; ahora solo se trabaja en el motor (`crates/core`) y la CLI.

## Propiedad de módulos

| Módulo | Dueño | Contenido |
| --- | --- | --- |
| `types.rs`, `cmd.rs`, `lib.rs`, `crates/cli` | Lead | Tipos compartidos, ejecución de comandos, orquestación |
| `detect/` | Detección | Superbloque, features por modo, LUKS/LVM |
| `send/` | Modo send | Snapshots, send/receive, zstd, incrementales, restore, tabla de particiones/ESP/UUID |
| `verify/` | Verificación | Restauración de prueba y comprobaciones |
| `report/` | Informe | JSON, HTML, firma ed25519, versiones del esquema |
| `tests/` | Tests | Fixtures, arnés de regresión, control negativo |

- Cada agente toca solo su módulo.
- Un cambio en `types.rs`, `cmd.rs`, `lib.rs` o la CLI se pide al lead, no se hace directamente.
  Si hace falta un tipo nuevo, se define en local en el módulo y se propone al lead para moverlo.

## Seguridad: solo loop devices

- **Prohibido** operar sobre `/dev/nvme*`, `/dev/sd*` o cualquier dispositivo real.
- Solo loop devices sobre archivos dentro del directorio de pruebas (un `tempdir`).
- Exporta siempre `PARTSHIELD_SANDBOX=1`. Con él, `Session` rechaza cualquier comando
  que nombre un `/dev/` que no sea `/dev/loop*`, y `cmd::guard_path` hace lo mismo para
  el código que abre rutas directamente. Todo acceso directo a un dispositivo debe
  pasar por `guard_path`.
- Antes de soltar un loop device, desmóntalo; libera siempre lo que crees (también si el test falla).

## Hecho significa

1. `cargo fmt --check`, `cargo clippy --all-targets` sin avisos y `cargo test` en verde.
2. La puerta de la Fase 0 en verde:
   `sudo PARTSHIELD_SANDBOX=1 PARTSHIELD_E2E=1 cargo test --test e2e`
   (restaurar y montar una copia de un Btrfs con `BLOCK_GROUP_TREE`).
