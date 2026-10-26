#!/bin/bash
# Arranca la ISO en QEMU y comprueba por el puerto serie que llega al sistema.
#
#   iso/test/boot-test.sh ISO bios|uefi|secureboot|selftest [más modos...]
#
# - bios        SeaBIOS (arranque por isolinux)
# - uefi        OVMF sin Secure Boot
# - secureboot  OVMF con Secure Boot activado y las claves de Microsoft:
#               exige secureboot=1 en el anuncio (shim y GRUB firmados)
# - selftest    UEFI + autoprueba de copia y verificación dentro de la ISO,
#               pedida con una credencial SMBIOS (no toca el menú de arranque)
#
# Se ejecuta en un contenedor Debian 13 (usa el OVMF de Debian). Con /dev/kvm
# tarda segundos; sin él (emulación TCG), varios minutos por modo.
set -euo pipefail

ISO=$(readlink -f "$1"); shift
[ -f "$ISO" ] || { echo "no existe la ISO $ISO" >&2; exit 2; }
MODES=("$@")
[ ${#MODES[@]} -gt 0 ] || MODES=(bios uefi secureboot selftest gui)
HERE=$(cd "$(dirname "$0")" && pwd)
LOGS="$(dirname "$ISO")/boot-logs"
mkdir -p "$LOGS"

KVM=()
[ -e /dev/kvm ] && KVM=(--device /dev/kvm)

docker run --rm "${KVM[@]}" -v "$ISO:/iso/test.iso:ro" -v "$LOGS:/logs" \
    -v "$HERE/qemu-boot.sh:/qemu-boot.sh:ro" debian:trixie \
    bash /qemu-boot.sh "${MODES[@]}"
