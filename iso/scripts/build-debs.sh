#!/bin/bash
# Compila partclone, btrfs-progs y partshield y los empaqueta como .deb.
# Se ejecuta DENTRO de un contenedor Debian 13 (ver ../build.sh):
#   /src  = raíz de partshield (solo lectura)
#   /out  = salida (/out/debs/*.deb)
set -euo pipefail

. /src/iso/versions.env
WORK=/tmp/debs-work
OUT=/out/debs
mkdir -p "$WORK" "$OUT"
export DEBIAN_FRONTEND=noninteractive

log() { printf '\n==> %s\n' "$*"; }

log "Dependencias de compilación"
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    ca-certificates curl build-essential autoconf automake libtool pkg-config \
    gettext autopoint dpkg-dev xsltproc docbook-xsl docbook-xml \
    uuid-dev libblkid-dev zlib1g-dev libzstd-dev liblzo2-dev libudev-dev libxxhash-dev libssl-dev \
    libext2fs-dev libcom-err2 \
    libgtk-4-dev libadwaita-1-dev \
    cargo rustc >/dev/null

# mkdeb NOMBRE VERSIÓN DIRECTORIO DESCRIPCIÓN
# Crea /out/debs/NOMBRE_VERSIÓN_amd64.deb a partir de DIRECTORIO (un árbol
# instalado con DESTDIR). Calcula Depends con dpkg-shlibdeps.
mkdeb() {
    local name=$1 version=$2 root=$3 desc=$4 extra_depends=${5:-}
    local deps
    mkdir -p "$WORK/shlib-$name/debian"
    : > "$WORK/shlib-$name/debian/control"
    printf 'Source: %s\n\nPackage: %s\nArchitecture: amd64\n' "$name" "$name" \
        > "$WORK/shlib-$name/debian/control"
    mapfile -t elfs < <(find "$root" -type f -exec sh -c 'head -c4 "$1" | grep -q ELF && echo "$1"' _ {} \;)
    deps=$(cd "$WORK/shlib-$name" && dpkg-shlibdeps -O "${elfs[@]}" 2>/dev/null \
        | sed -n 's/^shlibs:Depends=//p')
    [ -n "$extra_depends" ] && deps="${deps:+$deps, }$extra_depends"
    mkdir -p "$root/DEBIAN"
    cat > "$root/DEBIAN/control" <<EOF
Package: $name
Version: $version
Architecture: amd64
Maintainer: PartShield <hola@partshield.io>
Depends: $deps
Section: admin
Priority: optional
Homepage: https://partshield.io
Description: $desc
 Compilado para la ISO de PartShield (versión fijada en iso/versions.env).
EOF
    dpkg-deb --root-owner-group -Zxz --build "$root" "$OUT/${name}_${version}_amd64.deb" >/dev/null
    echo "    $OUT/${name}_${version}_amd64.deb"
}

fetch() { # fetch URL DESTINO
    curl -fsSL --retry 4 --retry-delay 2 -o "$2" "$1"
}

# ---------------------------------------------------------------- partclone
log "partclone $PARTCLONE_VERSION"
cd "$WORK"
fetch "https://github.com/Thomas-Tsai/partclone/archive/refs/tags/$PARTCLONE_VERSION.tar.gz" partclone.tar.gz
rm -rf "partclone-$PARTCLONE_VERSION" && tar xzf partclone.tar.gz
cd "partclone-$PARTCLONE_VERSION"
./autogen >/dev/null 2>&1
./configure --prefix=/usr --sbindir=/usr/sbin --enable-btrfs >/dev/null
make -j"$(nproc)" >/dev/null
rm -rf "$WORK/root-partclone"
make install DESTDIR="$WORK/root-partclone" >/dev/null
rm -rf "$WORK/root-partclone/usr/share/locale" "$WORK/root-partclone/usr/share/info"
"$WORK/root-partclone/usr/sbin/partclone.btrfs" --version 2>&1 | head -1
mkdeb partclone "$PARTCLONE_VERSION-$DEB_REVISION" "$WORK/root-partclone" \
    "Copia de particiones por bloques usados (solo btrfs en esta compilación)"

# -------------------------------------------------------------- btrfs-progs
log "btrfs-progs $BTRFS_PROGS_VERSION"
cd "$WORK"
fetch "https://github.com/kdave/btrfs-progs/archive/refs/tags/v$BTRFS_PROGS_VERSION.tar.gz" btrfs-progs.tar.gz
rm -rf "btrfs-progs-$BTRFS_PROGS_VERSION" && tar xzf btrfs-progs.tar.gz
cd "btrfs-progs-$BTRFS_PROGS_VERSION"
./autogen.sh >/dev/null 2>&1
./configure --prefix=/usr --disable-documentation --disable-convert --disable-python >/dev/null
make -j"$(nproc)" >/dev/null
rm -rf "$WORK/root-btrfs"
make install DESTDIR="$WORK/root-btrfs" >/dev/null
# Solo las herramientas: las bibliotecas siguen siendo las de Debian
# (libbtrfsutil1t64), para no pisar archivos de otro paquete.
rm -rf "$WORK/root-btrfs/usr/lib" "$WORK/root-btrfs/usr/include"
"$WORK/root-btrfs/usr/bin/btrfs" --version
mkdeb btrfs-progs "$BTRFS_PROGS_VERSION-$DEB_REVISION" "$WORK/root-btrfs" \
    "Herramientas de Btrfs (mkfs.btrfs, btrfs, btrfs check, btrfstune...)"

# --------------------------------------------------------------- partshield
PS_VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' /src/Cargo.toml | head -1)
log "partshield $PS_VERSION (rustc $(rustc --version | cut -d' ' -f2))"
rm -rf "$WORK/partshield-src" && cp -a /src "$WORK/partshield-src" && rm -rf "$WORK/partshield-src/target"
cd "$WORK/partshield-src"
cargo build --release --locked -p partshield -p partshield-gui -q
rm -rf "$WORK/root-partshield"
install -Dm755 target/release/partshield "$WORK/root-partshield/usr/bin/partshield"
install -Dm644 README.md "$WORK/root-partshield/usr/share/doc/partshield/README.md"
mkdeb partshield "$PS_VERSION-$DEB_REVISION" "$WORK/root-partshield" \
    "Copias de Btrfs que no se dan por buenas hasta restaurarlas" \
    "btrfs-progs (>= $BTRFS_PROGS_VERSION-$DEB_REVISION), partclone (>= $PARTCLONE_VERSION), util-linux, gdisk, fdisk, dosfstools, mtools, cryptsetup-bin, lvm2"

rm -rf "$WORK/root-gui"
install -Dm755 target/release/partshield-gui "$WORK/root-gui/usr/bin/partshield-gui"
mkdeb partshield-gui "$PS_VERSION-$DEB_REVISION" "$WORK/root-gui" \
    "Interfaz gráfica de PartShield (GTK 4 + libadwaita)" \
    "partshield (= $PS_VERSION-$DEB_REVISION)"

log "Paquetes listos"
ls -la "$OUT"
