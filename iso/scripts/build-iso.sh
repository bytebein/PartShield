#!/bin/bash
# Construye la ISO con live-build. Se ejecuta DENTRO de un contenedor
# Debian 13 con privilegios (ver ../build.sh):
#   /src  = raíz de partshield (solo lectura)
#   /out  = salida; los .deb de build-debs.sh están en /out/debs
set -euo pipefail

. /src/iso/versions.env
export DEBIAN_FRONTEND=noninteractive
log() { printf '\n==> %s\n' "$*"; }

ls /out/debs/partshield_*.deb /out/debs/btrfs-progs_*.deb /out/debs/partclone_*.deb >/dev/null \
    || { echo "faltan los .deb: ejecuta primero iso/build.sh debs" >&2; exit 1; }

log "Herramientas"
apt-get update -qq
apt-get install -y -qq --no-install-recommends live-build debootstrap ca-certificates >/dev/null
lb --version

# Réplicas: snapshot.debian.org fijado por fecha (reproducible) o deb.debian.org.
SNAP=${DEBIAN_SNAPSHOT:-$DEBIAN_SNAPSHOT}
if [ -n "$SNAP" ]; then
    export PS_MIRROR="http://snapshot.debian.org/archive/debian/$SNAP/"
    export PS_MIRROR_SECURITY="http://snapshot.debian.org/archive/debian-security/$SNAP/"
else
    export PS_MIRROR="http://deb.debian.org/debian/"
    export PS_MIRROR_SECURITY="http://security.debian.org/debian-security/"
fi
log "Réplica: $PS_MIRROR"

B=/build
rm -rf "$B" && mkdir -p "$B"
cp -a /src/iso/live/. "$B/"
mkdir -p "$B/config/packages.chroot"
cp /out/debs/*.deb "$B/config/packages.chroot/"
cd "$B"

log "lb config"
chmod +x auto/config
lb config >/dev/null
# Si auto/config no se ejecutó, live-build construye con sus valores por
# defecto (testing, sin Secure Boot) sin avisar. Mejor fallar.
grep -q '^LB_DISTRIBUTION="trixie"' config/bootstrap \
    || { echo "lb config no aplicó auto/config (¿no es ejecutable?)" >&2; exit 1; }
grep -q '^LB_UEFI_SECURE_BOOT="enable"' config/binary \
    || { echo "lb config no activó Secure Boot" >&2; exit 1; }
log "lb build (tarda: debootstrap, paquetes, squashfs, ISO)"
lb build 2>&1 | tee /out/lb-build.log | grep -E '^P:|^E:|^W:' || true

ISO=$(ls "$B"/*.iso 2>/dev/null | head -1)
[ -n "$ISO" ] || { echo "lb build no produjo ISO; ver /out/lb-build.log" >&2; exit 1; }

PS_VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' /src/Cargo.toml | head -1)
NAME="partshield-$PS_VERSION-$(date -u +%Y%m%d)-amd64.iso"
cp "$ISO" "/out/$NAME"
cp "$B/chroot.packages.live" "/out/${NAME%.iso}.packages" 2>/dev/null || true
cd /out && sha256sum "$NAME" > "$NAME.sha256"
log "ISO lista"
ls -la "/out/$NAME" && cat "/out/$NAME.sha256"
