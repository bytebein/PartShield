#!/bin/bash
# Autoprueba desde la ISO: Btrfs con BLOCK_GROUP_TREE en un loop, copia con
# PartShield, verificación de cinco pasos. Solo se ejecuta si se pide
# (parámetro de arranque partshield.selftest o credencial SMBIOS del mismo
# nombre). Escribe PARTSHIELD_SELFTEST=OK o =FAIL en la consola.
set -u
export PARTSHIELD_SANDBOX=1
W=/run/partshield-selftest
mkdir -p "$W/origen" "$W/copias" "$W/scratch"
trap 'umount "$W/origen" 2>/dev/null; [ -n "${dev:-}" ] && losetup -d "$dev" 2>/dev/null' EXIT
# La consola principal es la pantalla (console=tty0 va la última); las
# marcas de prueba van también al puerto serie, que es el que lee QEMU.
say() { echo "$*"; [ -w /dev/ttyS0 ] && echo "$*" > /dev/ttyS0 2>/dev/null; true; }
fail() { say "PARTSHIELD_SELFTEST=FAIL $*"; exit 1; }

truncate -s 512M "$W/origen.img"
mkfs.btrfs -q -O block-group-tree "$W/origen.img" || fail mkfs
dev=$(losetup --find --show "$W/origen.img") || fail losetup
mount -o compress=zstd "$dev" "$W/origen" || fail mount
btrfs -q subvolume create "$W/origen/datos" || fail subvol
cp -a /etc /usr/share/doc "$W/origen/datos/" 2>/dev/null
sync

partshield -q backup "$W/origen/datos" --dest "$W/copias" \
    --snapshot-dir "$W/origen" --scratch-dir "$W/scratch" > "$W/backup.log" 2>&1
rc=$?
tail -8 "$W/backup.log"
[ $rc -eq 0 ] || fail "partshield backup salió con $rc"
grep -q "COPIA VÁLIDA" "$W/backup.log" || fail "veredicto distinto de válida"
say "PARTSHIELD_SELFTEST=OK"
