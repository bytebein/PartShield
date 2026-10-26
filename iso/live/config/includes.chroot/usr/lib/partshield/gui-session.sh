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
                if (dpi >= 240) print 2; else if (dpi >= 160) print 1.5; else print 1
            }
        }')
fi
if [ -n "$scale" ] && [ "$scale" != 1 ] && [ -n "$out" ]; then
    wlr-randr --output "$out" --scale "$scale" || true
fi
# Una ejecución de la interfaz; deja su código de salida en $RC.
# PARTSHIELD_GUI_READY va también al puerto serie, para las pruebas en QEMU.
RC=/run/partshield/gui.rc
mkdir -p /run/partshield
run() {
    if [ -w /dev/ttyS0 ]; then
        { partshield-gui; echo $? > "$RC"; } | tee /dev/ttyS0
    else
        partshield-gui
        echo $? > "$RC"
    fi
}

# «Salir a la consola» sale con 0. Si se cae, se relanza (hasta 3 veces)
# en vez de dejar la pantalla en una consola.
tries=0
while :; do
    run
    rc=$(cat "$RC" 2>/dev/null || echo 1)
    [ "$rc" = 0 ] && exit 0
    tries=$((tries + 1))
    echo "partshield-gui salió con el código $rc ($tries/3)" >&2
    [ $tries -ge 3 ] && exit "$rc"
    sleep 1
done
