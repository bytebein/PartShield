# Roadmap de PartShield

La interfaz actual funciona, pero enseña demasiado: subvolúmenes, send/raw y
los cinco pasos de verificación. La idea es que una copia sean cuatro clics
y una barra de progreso, y que todo lo demás quede en un modo avanzado.

## Antes de hacerlo público

1. ~~Repo propio con CI, README y licencia.~~ Hecho: `bytebein/PartShield`,
   GPL-3.0.
2. Copia real de un disco de uso diario (Btrfs, ~653 GiB), restaurada y
   verificada de principio a fin en hardware real.

## Hecho

- Inicio con «Hacer copia» y «Restaurar» (Restaurar, pendiente), interruptor
  «Avanzado» y menú «Herramientas».
- Copia sencilla: disco entero o particiones con casillas, destino en otro
  disco, una barra y resultado en verde, ámbar o rojo.
- Disco entero: tabla de particiones (`sfdisk --dump`) más cada partición;
  Btrfs por send, el resto sector a sector.
- Paso «estructura» para ext2/3/4, vfat, exFAT, XFS y NTFS con su fsck de
  solo lectura: una copia de esas particiones ya puede salir válida.

## Modo básico

Es el modo por defecto: la live arranca siempre en básico.

**Pantalla inicial:** dos botones, «Hacer copia» y «Restaurar».

**Hacer copia**, al estilo de Acronis:

1. **Origen:** árbol de discos. Viene marcado el disco entero; también se
   puede elegir una partición suelta.
2. **Destino:** solo discos externos, con aviso de si cabe o no cabe.
3. **Progreso:** una sola barra que junta copia y verificación, con
   porcentaje y tiempo restante.
4. **Resultado:**
   - 🟢 Copia comprobada: se puede restaurar.
   - 🟡 Copia hecha, pero no se pudo comprobar del todo.
   - 🔴 Esta copia no vale.

**Restaurar:** elegir la copia (la más reciente primero), elegir el disco y
empezar.

Todo lo que borra un disco pide confirmarlo por modelo y número de serie,
también en modo básico.

Lo que el modo básico decide solo:

- Todos los subvolúmenes, sin snapshots.
- Send o raw según el contenido del disco.
- Verificación completa siempre; no se puede saltar.
- Informe firmado guardado junto a la copia.

## Modo avanzado

Se activa con un interruptor arriba. Incluye:

- Lo que hay ahora: elección de subvolúmenes, método y detalle de los cinco
  pasos de verificación.
- Extras:
  - incluir snapshots
  - exclusiones
  - tamaño de la muestra
  - claves de firma
  - log en vivo
  - volver a verificar una copia antigua
  - abrir LUKS

## Dispositivos externos

- Al arrancar se montan todos **solo lectura**, y se detectan las copias que
  ya tengan para ofrecerlas en «Restaurar».
- Solo el destino elegido pasa a lectura-escritura, y solo mientras copia.
- Un origen montado se desmonta solo antes de copiar.

## Herramientas

Botón aparte para utilidades:

- **GParted**, con Xwayland en la ISO. Falta resolver los permisos de root
  dentro de cage: o se lanza como root, o se añade un agente de polkit.
- Más adelante: terminal y estado SMART del disco.

PartShield no formatea discos. Si el destino no sirve, se prepara antes con
GParted.

## Trabajo técnico nuevo

- **Copia del disco entero:** la tabla de particiones más cada partición.
  - Btrfs, como hasta ahora.
  - NTFS, EFI y el resto, como imagen de los bloques usados.
  - Cada partición se verifica restaurándola. Para NTFS: montar solo lectura
    y comparar.
- **NTFS sucio** (Windows hibernado o con inicio rápido): avisar y no copiar.
- **Barra de progreso** con porcentaje real. Ahora avanza por partes (copia y
  comprobación); en una imagen sector a sector grande se queda quieta hasta
  terminar la copia.
- **Restaurar desde la interfaz.**
- GParted y Xwayland en la ISO (el botón ya existe y se activa si está).
