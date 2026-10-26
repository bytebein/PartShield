#!/bin/bash
# Dentro del contenedor de boot-test.sh: arranca /iso/test.iso en cada modo.
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq --no-install-recommends qemu-system-x86 ovmf socat >/dev/null

if [ -e /dev/kvm ]; then ACCEL=(-accel kvm -cpu host); TIMEOUT=600
else ACCEL=(-accel tcg -cpu max); TIMEOUT=${BOOT_TIMEOUT:-2400}; fi
OVMF=/usr/share/OVMF
fail=0

boot() { # boot MODO
    local mode=$1 log=/logs/$1.log want=PARTSHIELD_READY
    local fw=() extra=()
    case $mode in
        bios|gui) ;;
        uefi|selftest)
            cp $OVMF/OVMF_VARS_4M.fd /tmp/vars-$mode.fd
            fw=(-drive if=pflash,format=raw,unit=0,readonly=on,file=$OVMF/OVMF_CODE_4M.fd
                -drive if=pflash,format=raw,unit=1,file=/tmp/vars-$mode.fd) ;;
        secureboot)
            cp $OVMF/OVMF_VARS_4M.ms.fd /tmp/vars-sb.fd
            fw=(-global driver=cfi.pflash01,property=secure,value=on
                -drive if=pflash,format=raw,unit=0,readonly=on,file=$OVMF/OVMF_CODE_4M.secboot.fd
                -drive if=pflash,format=raw,unit=1,file=/tmp/vars-sb.fd) ;;
        *) echo "modo desconocido: $mode"; return 1 ;;
    esac
    [ "$mode" = selftest ] && { extra=(-smbios type=11,value=io.systemd.credential:partshield.selftest=1); want=PARTSHIELD_SELFTEST=; }
    [ "$mode" = gui ] && want=PARTSHIELD_GUI_READY
    local machine=q35
    [ "$mode" = secureboot ] && machine=q35,smm=on

    : > "$log"
    timeout $((TIMEOUT + 60)) qemu-system-x86_64 -machine $machine "${ACCEL[@]}" -m 3072 -smp 2 \
        "${fw[@]}" "${extra[@]}" -cdrom /iso/test.iso -boot d \
        -display none -serial file:"$log" -no-reboot \
        -monitor unix:/tmp/mon-$mode.sock,server,nowait &
    local pid=$! start=$SECONDS
    while kill -0 $pid 2>/dev/null && [ $((SECONDS - start)) -lt $TIMEOUT ]; do
        grep -qa "$want" "$log" && break
        sleep 5
    done
    if [ "$mode" = gui ] && grep -qa "$want" "$log"; then
        # Sin KVM la primera ventana tarda en pintarse: varias capturas.
        for t in ${GUI_SHOTS:-20 60 120 180}; do
            sleep $((t - ${prev:-0})); prev=$t
            echo "screendump /logs/gui-${t}s.ppm" | socat - UNIX-CONNECT:/tmp/mon-$mode.sock >/dev/null
        done
        cp /logs/gui-${t}s.ppm /logs/gui.ppm
        sleep 2
    fi
    kill $pid 2>/dev/null; wait $pid 2>/dev/null
    local line; line=$(grep -a "$want" "$log" | tail -1 | tr -d '\r')
    local secs=$((SECONDS - start))
    if [ -z "$line" ]; then
        echo "FALLO  $mode: sin $want en ${secs}s (últimas líneas del serie:)"; tail -5 "$log" | tr -d '\r' | sed 's/^/        /'
        return 1
    fi
    case $mode in
        secureboot) [[ $line == *secureboot=1* ]] || { echo "FALLO  $mode: arrancó sin Secure Boot: $line"; return 1; } ;;
        uefi) [[ $line == *secureboot=0* ]] || { echo "FALLO  $mode: $line"; return 1; } ;;
        bios) [[ $line == *secureboot=bios* ]] || { echo "FALLO  $mode: $line"; return 1; } ;;
        gui) [ -s /logs/gui.ppm ] || { echo "FALLO  $mode: sin captura de pantalla"; return 1; } ;;
        selftest) [[ $line == *=OK* ]] || { echo "FALLO  $mode: $line"; return 1; } ;;
    esac
    echo "OK     $mode (${secs}s): ${line#*PARTSHIELD_}"
}

for m in "$@"; do boot "$m" || fail=1; done
exit $fail
