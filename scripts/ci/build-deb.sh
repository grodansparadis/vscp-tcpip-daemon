#!/usr/bin/env bash
#
# Build a Debian package (.deb) of vscpd inside a Debian-based environment.
# Used by .github/workflows/debian-packages.yml for Debian (amd64) and
# Raspberry Pi OS (arm64/armhf), but it can also be run manually, e.g.
#
#   docker run --rm -v "$PWD:/src" -w /src debian:bookworm \
#       scripts/ci/build-deb.sh bookworm
#
# Argument 1: distribution codename used in the output file name (default:
#             taken from /etc/os-release).
# Output:     dist/vscp-tcpip-daemon_<version>_<codename>_<arch>.deb

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${SRC_DIR}/build-deb}"
DIST_DIR="${DIST_DIR:-${SRC_DIR}/dist}"

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

if [ "${SKIP_DEPS:-0}" != "1" ]; then
    ${SUDO} apt-get update -qq
    ${SUDO} apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build pkg-config git ca-certificates \
        file dpkg-dev pandoc \
        libssl-dev libexpat1-dev zlib1g-dev libcurl4-openssl-dev \
        libsqlite3-dev libsystemd-dev libsodium-dev
fi

# shellcheck disable=SC1091
. /etc/os-release
CODENAME="${1:-${VERSION_CODENAME:-unknown}}"
ARCH="$(dpkg --print-architecture)"

# The source tree is usually bind-mounted into a container owned by another user.
git config --global --add safe.directory '*' 2>/dev/null || true

cmake -S "${SRC_DIR}" -B "${BUILD_DIR}" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DVSCPD_ENABLE_SYSTEMD=ON

cmake --build "${BUILD_DIR}" --parallel "$(nproc)"

(cd "${BUILD_DIR}" && cpack -G DEB)

mkdir -p "${DIST_DIR}"
for deb in "${BUILD_DIR}"/*.deb; do
    pkg="$(dpkg-deb -f "${deb}" Package)"
    ver="$(dpkg-deb -f "${deb}" Version)"
    out="${DIST_DIR}/${pkg}_${ver}_${CODENAME}_${ARCH}.deb"
    cp "${deb}" "${out}"
    echo "==> ${out}"
    dpkg-deb --info "${out}"
done
