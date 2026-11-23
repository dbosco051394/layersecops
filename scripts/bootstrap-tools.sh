#!/usr/bin/env bash
# Install Trivy, Grype, Syft and Dive into ./.tools/bin.
#
# Usage:
#   scripts/bootstrap-tools.sh
#   scripts/bootstrap-tools.sh --dir /usr/local/bin
#   TRIVY_VERSION=0.58.0 scripts/bootstrap-tools.sh --tools trivy,grype
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${ROOT}/.tools/bin"
TOOLS="trivy,grype,syft,dive"
FORCE=0

usage() {
  cat <<'EOF'
Usage: bootstrap-tools.sh [--dir DIR] [--tools LIST] [--force]

  --dir DIR      install directory (default: <repo>/.tools/bin)
  --tools LIST   comma-separated subset of trivy,grype,syft,dive
  --force        reinstall even if the tool already exists

Environment:
  TRIVY_VERSION, GRYPE_VERSION, SYFT_VERSION, DIVE_VERSION
                 pin a version instead of querying the latest release
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) DEST="$2"; shift 2 ;;
    --tools) TOOLS="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 2; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 2; }

OS="$(uname -s)"
ARCH="$(uname -m)"
case "${OS}" in
  Linux) PLATFORM="linux" ;;
  Darwin) PLATFORM="darwin" ;;
  *) echo "Unsupported OS: ${OS}. On Windows use scripts/bootstrap-tools.ps1." >&2; exit 2 ;;
esac
case "${ARCH}" in
  x86_64|amd64) ARCH_GO="amd64"; TRIVY_ARCH="64bit" ;;
  aarch64|arm64) ARCH_GO="arm64"; TRIVY_ARCH="ARM64" ;;
  *) echo "Unsupported architecture: ${ARCH}" >&2; exit 2 ;;
esac
if [[ "${PLATFORM}" == "darwin" ]]; then
  TRIVY_OS="macOS"
else
  TRIVY_OS="Linux"
fi

latest_version() {
  local repo="$1"
  local tag
  tag="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' \
    | head -n 1)"
  if [[ -z "${tag}" ]]; then
    echo "Could not determine the latest version for ${repo}" >&2
    return 1
  fi
  echo "${tag}"
}

install_tool() {
  local name="$1" version="$2" url="$3"
  local target="${DEST}/${name}"
  if [[ -x "${target}" && ${FORCE} -eq 0 ]]; then
    echo "  ${name}: already installed at ${target} ($("${target}" --version 2>/dev/null | head -n 1 || true))"
    return 0
  fi

  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' RETURN
  echo "  ${name}: downloading ${url}"
  curl -fsSL "${url}" -o "${tmp}/archive.tar.gz"
  tar -xzf "${tmp}/archive.tar.gz" -C "${tmp}"
  local binary
  binary="$(find "${tmp}" -type f -name "${name}" -perm -u+x | head -n 1)"
  if [[ -z "${binary}" ]]; then
    binary="$(find "${tmp}" -type f -name "${name}" | head -n 1)"
  fi
  if [[ -z "${binary}" ]]; then
    echo "Could not find the ${name} binary in the downloaded archive" >&2
    return 1
  fi
  install -m 0755 "${binary}" "${target}"
  echo "  ${name}: installed ${version} at ${target}"
}

mkdir -p "${DEST}"
echo "Installing tools into ${DEST} (${PLATFORM}/${ARCH_GO})"

IFS=',' read -r -a SELECTED <<< "${TOOLS}"
for tool in "${SELECTED[@]}"; do
  case "${tool}" in
    trivy)
      V="${TRIVY_VERSION:-$(latest_version aquasecurity/trivy)}"
      install_tool trivy "${V}" \
        "https://github.com/aquasecurity/trivy/releases/download/v${V}/trivy_${V}_${TRIVY_OS}-${TRIVY_ARCH}.tar.gz"
      ;;
    grype)
      V="${GRYPE_VERSION:-$(latest_version anchore/grype)}"
      install_tool grype "${V}" \
        "https://github.com/anchore/grype/releases/download/v${V}/grype_${V}_${PLATFORM}_${ARCH_GO}.tar.gz"
      ;;
    syft)
      V="${SYFT_VERSION:-$(latest_version anchore/syft)}"
      install_tool syft "${V}" \
        "https://github.com/anchore/syft/releases/download/v${V}/syft_${V}_${PLATFORM}_${ARCH_GO}.tar.gz"
      ;;
    dive)
      V="${DIVE_VERSION:-$(latest_version wagoodman/dive)}"
      install_tool dive "${V}" \
        "https://github.com/wagoodman/dive/releases/download/v${V}/dive_${V}_${PLATFORM}_${ARCH_GO}.tar.gz"
      ;;
    *) echo "Unknown tool: ${tool}" >&2; exit 2 ;;
  esac
done

echo ""
echo "Done. Add ${DEST} to PATH or use scripts/scan.sh, which does it automatically."
