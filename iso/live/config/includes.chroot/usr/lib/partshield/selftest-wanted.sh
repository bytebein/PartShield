#!/bin/sh
# ¿Se ha pedido la autoprueba? Sale con 0 si sí. Se comprueba en tres sitios
# porque cada forma de arrancar la ISO deja la marca en uno distinto:
#  - parámetro de arranque partshield.selftest
#  - credencial de systemd partshield.selftest (SMBIOS tipo 11 importada)
#  - la propia tabla SMBIOS tipo 11 (cadenas OEM), por si systemd no la importó
grep -qw 'partshield.selftest' /proc/cmdline && exit 0
for d in /run/credentials/@system /run/credentials/@initrd; do
    [ -e "$d/partshield.selftest" ] && exit 0
done
for f in /sys/firmware/dmi/entries/11-*/raw; do
    [ -r "$f" ] && tr '\0' '\n' < "$f" | grep -q 'partshield.selftest' && exit 0
done
exit 1
