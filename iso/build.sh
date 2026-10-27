#!/bin/bash
# Construye la ISO de PartShield en un contenedor Debian 13 con privilegios.
#
#   iso/build.sh debs     compila partclone, btrfs-progs y partshield (.deb)
#   iso/build.sh iso      construye la ISO con live-build (usa los .deb)
#   iso/build.sh all      las dos cosas
#
# Salida en iso/out/: debs/*.deb, partshield-<versión>-amd64.iso y su SHA256SUMS.
# Requiere Docker y un kernel con loop devices. Nada de esto toca discos del host.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
OUT="$HERE/out"
IMAGE=debian:trixie
mkdir -p "$OUT"

# Redes con proxy que re-termina TLS: EXTRA_CA_BUNDLE=/ruta/ca.crt iso/build.sh
CA_ARGS=()
if [ -n "${EXTRA_CA_BUNDLE:-}" ]; then
    CA=/etc/ssl/certs/partshield-extra-ca.pem
    CA_ARGS=(-v "$EXTRA_CA_BUNDLE:$CA:ro" -e SSL_CERT_FILE=$CA -e CURL_CA_BUNDLE=$CA
             -e CARGO_HTTP_CAINFO=$CA -e GIT_SSL_CAINFO=$CA)
fi

run() { # run SCRIPT
    docker run --rm --privileged "${CA_ARGS[@]}" \
        -v "$ROOT:/src:ro" -v "$OUT:/out" \
        -e DEBIAN_SNAPSHOT="${DEBIAN_SNAPSHOT:-}" \
        "$IMAGE" bash "/src/iso/scripts/$1"
}

case "${1:-all}" in
    debs) run build-debs.sh ;;
    iso) run build-iso.sh ;;
    all) run build-debs.sh && run build-iso.sh ;;
    *) echo "uso: $0 debs|iso|all" >&2; exit 2 ;;
esac
