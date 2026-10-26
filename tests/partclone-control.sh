#!/usr/bin/env bash
# Control negativo (y positivo) con partclone sobre un Btrfs con BLOCK_GROUP_TREE.
#
# partclone < 0.3.49 no copia el chunk_root de un Btrfs con BLOCK_GROUP_TREE
# (https://github.com/Thomas-Tsai/partclone/issues/303, arreglado en el PR #305;
# más arreglos de btrfs en 0.3.50, commit fcbeab2). Rescuezilla usa 0.3.47.
#
# Uso:
#   partclone-control.sh build <tag> [distro|pattern] compila en /tmp/partclone-bin/<tag>[-variante]/
#   partclone-control.sh run <partclone.btrfs> [fresh|heavy]
#   partclone-control.sh all                          compila 0.3.47, 0.3.47-pattern y 0.3.50
#                                                     y ejecuta fresh y heavy con cada uno
#
# `run` crea un Btrfs con -O block-group-tree sobre un loop device, lo llena,
# hace `partclone.btrfs -c`, restaura con `-r` sobre otro loop device, y
# prueba `btrfs check --readonly`, `mount` y la comparación de contenido.
# Imprime una línea final `RESULT ...` que lee el test Rust
# (crates/core/tests/partclone_control.rs).
#
# Seguridad: solo loop devices sobre archivos bajo /tmp; todo /dev/ que se usa
# se comprueba antes con `only_loop`. Requiere root.

set -uo pipefail
export PARTSHIELD_SANDBOX=1
export LC_ALL=C

REPO=https://github.com/Thomas-Tsai/partclone
WORK=${PARTCLONE_WORK:-/tmp/partclone-work}
BIN=${PARTCLONE_BIN:-/tmp/partclone-bin}

die() { echo "error: $*" >&2; exit 2; }

# Aborta si algún argumento es un /dev/ que no sea /dev/loop*.
only_loop() {
    local a
    for a in "$@"; do
        case "$a" in
            /dev/loop[0-9]*) ;;
            /dev/*) die "PARTSHIELD_SANDBOX: $a no es un loop device; abortado" ;;
        esac
    done
}

# build <tag> [variante]
#   variante vacía: CFLAGS de partclone (-g -O2 -Wall)
#   distro:  CFLAGS de un paquete Ubuntu/Debian (dpkg-buildflags)
#   pattern: además -ftrivial-auto-var-init=pattern, que da a las variables
#            sin inicializar un valor basura fijo (0xfe…) en vez del que deje
#            la pila; hace determinista el fallo de 0.3.47: en
#            dump_start_leaf() la variable `size` de los nodos interiores no
#            se inicializa (arreglado en 0.3.50), y con basura no alineada
#            check_extent_bitmap() descarta el nodo, p. ej. la raíz de un
#            chunk tree de nivel 1. Con -O2 a secas la pila suele contener
#            16384 (de la llamada anterior) y el fallo no aparece.
#   zero:    -ftrivial-auto-var-init=zero. NO lo dispara: con size=0,
#            set_bitmap() marca igualmente el primer bloque (comprobado).
build() {
    local tag=$1 variant=${2:-} v=$1 cflags="-g -O2 -Wall"
    [ -n "$variant" ] && v="$tag-$variant"
    case "$variant" in
        "") ;;
        distro) cflags=$(dpkg-buildflags --get CFLAGS 2>/dev/null || echo "-g -O2 -fstack-protector-strong") ;;
        pattern) cflags="-g -O2 -Wall -ftrivial-auto-var-init=pattern" ;;
        zero) cflags="-g -O2 -Wall -ftrivial-auto-var-init=zero" ;;
        *) die "variante desconocida: $variant" ;;
    esac
    local src=$WORK/build-$v
    if [ -x "$BIN/$v/sbin/partclone.btrfs" ]; then
        echo "ya compilado: $BIN/$v/sbin/partclone.btrfs"
        return 0
    fi
    command -v apt-get >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        git autoconf automake libtool pkg-config gettext autopoint uuid-dev libblkid-dev \
        libssl-dev libncursesw5-dev e2fslibs-dev libxxhash-dev >/dev/null
    mkdir -p "$WORK"
    rm -rf "$src"
    git clone -q --depth 1 --branch "$tag" "$REPO" "$src" 2>/dev/null || die "git clone $tag"
    (
        cd "$src" || exit 1
        ./autogen >"$WORK/autogen-$v.log" 2>&1
        CFLAGS="$cflags" ./configure --enable-btrfs --prefix="$BIN/$v" >"$WORK/configure-$v.log" 2>&1 || exit 1
        make -j"$(nproc)" >"$WORK/make-$v.log" 2>&1 || exit 1
        # La instalación de las páginas man falla sin xsltproc; los binarios sí se instalan.
        make install >"$WORK/install-$v.log" 2>&1 || true
    ) || die "compilando $v (logs en $WORK)"
    [ -x "$BIN/$v/sbin/partclone.btrfs" ] || die "no se instaló $BIN/$v/sbin/partclone.btrfs"
    "$BIN/$v/sbin/partclone.btrfs" --version 2>&1 | head -1
    rm -rf "$src"
}

LOOPS=()
MNTS=()
cleanup() {
    local m l
    for m in "${MNTS[@]}"; do umount "$m" 2>/dev/null; done
    for l in "${LOOPS[@]}"; do only_loop "$l" && losetup -d "$l" 2>/dev/null; done
    [ -n "${RUN_DIR:-}" ] && rm -rf "$RUN_DIR"
}

# attach <imagen> <var>: asocia un loop device y lo guarda en <var>.
attach() {
    local dev
    dev=$(losetup --find --show "$1") || die "losetup $1"
    only_loop "$dev"
    [ -n "$dev" ] || die "losetup no devolvió dispositivo"
    LOOPS+=("$dev")
    printf -v "$2" '%s' "$dev"
}

# Llena el Btrfs montado en $1.
#
# `fresh`: unos pocos archivos; todos los árboles caben en una hoja.
# `heavy`: árboles de varios niveles. Con ~170 chunks de datos el chunk tree
#   ya no cabe en una hoja de 16 KiB (unos 150 CHUNK_ITEM por hoja) y su raíz
#   pasa a ser un nodo interior, igual que en un disco real de cientos de GB.
#   Para no escribir cientos de GB: en cada chunk queda un archivo de 8 KiB
#   y el resto se ocupa con `fallocate` (no escribe datos) y luego se borra.
#   20 000 archivos pequeños hacen además que el árbol del subvolumen tenga
#   varios niveles.
fill() {
    local mnt=$1 how=$2 i
    btrfs subvolume create "$mnt/datos" >/dev/null
    head -c 20M /dev/urandom >"$mnt/datos/aleatorio.bin"
    seq 1 200000 >"$mnt/datos/numeros.txt"
    mkdir -p "$mnt/datos/muchos"
    for i in $(seq 1 500); do echo "archivo $i" >"$mnt/datos/muchos/f$i"; done
    if [ "$how" = heavy ]; then
        mkdir -p "$mnt/datos/anclas" "$mnt/hueco" "$mnt/datos/pequenos"
        for i in $(seq 1 170); do
            head -c 8K /dev/urandom >"$mnt/datos/anclas/a$i"
            sync -f "$mnt"
            fallocate -l 1G "$mnt/hueco/h$i" || break
        done
        rm -rf "$mnt/hueco"
        for i in $(seq 1 20000); do echo "pequeño $i" >"$mnt/datos/pequenos/p$i"; done
        btrfs filesystem sync "$mnt" >/dev/null
    fi
    sync
}

run() {
    local pc=$1 how=${2:-fresh}
    [ -x "$pc" ] || die "no existe $pc"
    [ "$(id -u)" = 0 ] || die "hace falta root"
    local version
    version=$("$pc" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    RUN_DIR=$(mktemp -d /tmp/partshield-pcctl-XXXXXX)
    trap cleanup EXIT
    local size=1G
    [ "$how" = heavy ] && size=250G # disperso: en el host ocupa unos MB
    truncate -s "$size" "$RUN_DIR/origen.img" "$RUN_DIR/destino.img"
    mkdir -p "$RUN_DIR/m1" "$RUN_DIR/m2"
    mkfs.btrfs -q -O block-group-tree -L origen "$RUN_DIR/origen.img" || die mkfs
    local l1 l2
    attach "$RUN_DIR/origen.img" l1
    attach "$RUN_DIR/destino.img" l2
    only_loop "$l1" "$l2"

    mount -o compress=zstd "$l1" "$RUN_DIR/m1" || die "mount origen"
    MNTS+=("$RUN_DIR/m1")
    fill "$RUN_DIR/m1" "$how"
    (cd "$RUN_DIR/m1" && find datos -type f -print0 | sort -z | xargs -0 sha256sum) >"$RUN_DIR/sumas"
    local bgs
    bgs=$(btrfs inspect-internal dump-tree -t block-group "$l1" 2>/dev/null | grep -c BLOCK_GROUP_ITEM)
    umount "$RUN_DIR/m1"
    MNTS=()

    echo "== partclone $version, llenado $how, $bgs block groups"
    btrfs inspect-internal dump-super "$l1" | grep -E '^(chunk_root|chunk_root_level|compat_ro_flags|incompat_flags)\s'
    echo "niveles: chunk tree $(btrfs inspect-internal dump-tree -t chunk "$l1" | grep -m1 -oE '^(node|leaf) [0-9]+ level [0-9]+' || echo 'hoja (level 0)'), subvolumen $(btrfs inspect-internal dump-tree -t 256 "$l1" | grep -m1 -oE 'level [0-9]+' || echo 'level 0')"

    local chunk_root
    chunk_root=$(btrfs inspect-internal dump-super "$l1" | awk '$1 == "chunk_root" {print $2}')
    "$pc" -c -d3 -s "$l1" -o "$RUN_DIR/imagen.pc" -L "$RUN_DIR/clone.log" -q >/dev/null 2>&1
    local clone_rc=$?
    # Cómo marcó partclone el bloque de la raíz del chunk tree (log -d3).
    echo "-- chunk_root en el bitmap de partclone:"
    grep -E "check_extent_bitmap bytenr $chunk_root " "$RUN_DIR/clone.log" | sort | uniq -c | head -5
    [ -n "${KEEP_LOG:-}" ] && cp "$RUN_DIR/clone.log" "$KEEP_LOG"
    "$pc" -r -s "$RUN_DIR/imagen.pc" -o "$l2" -L "$RUN_DIR/restore.log" -q >/dev/null 2>&1
    local restore_rc=$?
    echo "clone rc=$clone_rc restore rc=$restore_rc"
    # Cuánto copió partclone (para ver si el bitmap se dejó bloques).
    grep -E 'used|Space in use|Block size' "$RUN_DIR/clone.log" | head -4

    # El restaurado lleva el mismo fsid que el origen: el origen va fuera
    # antes de montar para que el kernel no los confunda.
    losetup -d "$l1" && LOOPS=("$l2")

    local check_out check_rc
    check_out=$(btrfs check --readonly "$l2" 2>&1)
    check_rc=$?
    echo "-- btrfs check --readonly (rc=$check_rc):"
    echo "$check_out" | head -15

    local mount_out mount_rc compare=no-montado
    mount_out=$(mount -o ro "$l2" "$RUN_DIR/m2" 2>&1)
    mount_rc=$?
    echo "-- mount (rc=$mount_rc): $mount_out"
    if [ $mount_rc -ne 0 ]; then
        echo "-- dmesg:"
        dmesg 2>/dev/null | grep -i btrfs | tail -8
    else
        MNTS+=("$RUN_DIR/m2")
        local bad
        bad=$(cd "$RUN_DIR/m2" && sha256sum -c --quiet "$RUN_DIR/sumas" 2>&1 | grep -c -v '^$')
        if [ "$bad" = 0 ]; then
            compare=ok
        else
            compare=distinto
            echo "-- $bad archivos distintos o ilegibles; primeros:"
            (cd "$RUN_DIR/m2" && sha256sum -c --quiet "$RUN_DIR/sumas" 2>&1 | head -5)
        fi
    fi
    echo "RESULT bin=$pc version=$version fill=$how block_groups=$bgs clone=$clone_rc restore=$restore_rc check=$check_rc mount=$mount_rc content=$compare"
}

case "${1:-}" in
    build)
        shift
        [ $# -gt 0 ] || die "indica la versión"
        build "$@"
        ;;
    run)
        shift
        run "$@"
        ;;
    all)
        build 0.3.47
        build 0.3.47 pattern
        build 0.3.50
        for v in 0.3.47 0.3.47-pattern 0.3.50; do
            for how in fresh heavy; do
                (run "$BIN/$v/sbin/partclone.btrfs" "$how")
            done
        done 2>&1 | tee "$WORK/control.log"
        echo "== resumen (esperado: solo 0.3.47-pattern heavy con check=1 mount=32)"
        grep '^RESULT' "$WORK/control.log"
        ;;
    *)
        sed -n '2,20p' "$0"
        exit 2
        ;;
esac
