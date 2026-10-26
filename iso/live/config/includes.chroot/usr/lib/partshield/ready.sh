#!/bin/sh
# Anuncia en la consola (y en el puerto serie) que el sistema ha arrancado,
# con la versión y el estado de Secure Boot. Lo usan las pruebas de arranque.
# La consola principal es la pantalla (console=tty0 va la última); las
# marcas de prueba van también al puerto serie, que es el que lee QEMU.
say() { echo "$*"; [ -w /dev/ttyS0 ] && echo "$*" > /dev/ttyS0 2>/dev/null; true; }
sb=bios
if [ -d /sys/firmware/efi ]; then
    sb=0
    f=$(ls /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null || true)
    if [ -n "$f" ] && [ "$(od -An -t u1 -j4 -N1 "$f" | tr -d ' ')" = 1 ]; then
        sb=1
    fi
fi
ver=$(partshield --version 2>/dev/null | cut -d' ' -f2)
btrfs=$(btrfs --version 2>/dev/null | head -1 | cut -d' ' -f2)
pc=$(partclone.btrfs --version 2>&1 | grep -o 'v[0-9.]*' | head -1)
say "PARTSHIELD_READY version=$ver kernel=$(uname -r) secureboot=$sb btrfs-progs=$btrfs partclone=$pc"
