#!/bin/sh
# Se ejecuta dentro de cage: ajusta la escala a la densidad de la pantalla y
# lanza la interfaz. Con partshield.scale=N en la línea del kernel se fuerza.
scale=$(sed -n 's/.*partshield\.scale=\([0-9.]*\).*/\1/p' /proc/cmdline)
out=$(wlr-randr 2>/dev/null | awk '/^[^ ]/ {print $1; exit}')
if [ -z "$scale" ] && [ -n "$out" ]; then
    # Píxeles de ancho del modo actual / milímetros de ancho físicos → ppp.
    scale=$(wlr-randr --output "$out" 2>/dev/null | awk '
        /Physical size:/ { split($3, mm, "x"); w_mm = mm[1] }
        /current/ && !px { split($1, p, "x"); px = p[1] }
        END {
            if (w_mm > 0 && px > 0) {
                dpi = px / (w_mm / 25.4)
                if (dpi >= 190) print 2; else if (dpi >= 140) print 1.5; else print 1
            }
        }')
fi
if [ -n "$scale" ] && [ "$scale" != 1 ] && [ -n "$out" ]; then
    wlr-randr --output "$out" --scale "$scale" || true
fi
# PARTSHIELD_GUI_READY también al puerto serie, para las pruebas en QEMU.
if [ -w /dev/ttyS0 ]; then
    partshield-gui | tee /dev/ttyS0
else
    exec partshield-gui
fi
