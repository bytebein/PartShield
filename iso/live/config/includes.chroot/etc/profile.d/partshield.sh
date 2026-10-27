# Bienvenida en la consola del live USB.
if [ -t 1 ] && [ -z "${PARTSHIELD_WELCOMED:-}" ]; then
    export PARTSHIELD_WELCOMED=1
    cat <<'TXT'

  PartShield: copias de Btrfs que no se dan por buenas hasta restaurarlas.

    sudo partshield inspect /dev/sdXN              qué modos de copia son seguros
    sudo partshield backup /ruta --dest /mnt/usb   copia + verificación
    sudo partshield --help                         todo lo demás

  Interfaz gráfica: sudo systemctl start partshield-gui   (Alt+F7 / Alt+F1)

  Herramientas: ddrescue, testdisk, photorec, smartctl, nvme, sgdisk, cryptsetup.
  https://partshield.io

TXT
fi
