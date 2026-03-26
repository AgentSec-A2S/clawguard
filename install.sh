#!/bin/sh
set -e

REPO="AgentSec-A2S/clawguard"
BINARY="clawguard"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

detect_platform() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "$OS" in
    Darwin) OS="apple-darwin" ;;
    Linux)  OS="unknown-linux-gnu" ;;
    *)      echo "Unsupported OS: $OS" && exit 1 ;;
  esac

  case "$ARCH" in
    x86_64)  ARCH="x86_64" ;;
    aarch64) ARCH="aarch64" ;;
    arm64)   ARCH="aarch64" ;;
    *)       echo "Unsupported architecture: $ARCH" && exit 1 ;;
  esac

  TARGET="${ARCH}-${OS}"
}

get_latest_tag() {
  TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
  if [ -z "$TAG" ]; then
    echo "Failed to find latest release" && exit 1
  fi
}

download_and_install() {
  ARCHIVE="${BINARY}-${TAG}-${TARGET}.tar.gz"
  URL="https://github.com/${REPO}/releases/download/${TAG}/${ARCHIVE}"

  echo "Downloading ${BINARY} ${TAG} for ${TARGET}..."
  TMPDIR=$(mktemp -d)
  curl -fsSL "$URL" -o "${TMPDIR}/${ARCHIVE}"
  tar xzf "${TMPDIR}/${ARCHIVE}" -C "${TMPDIR}"

  mkdir -p "$INSTALL_DIR"
  mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
  chmod +x "${INSTALL_DIR}/${BINARY}"
  rm -rf "$TMPDIR"

  echo "Installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"
  echo ""

  if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo "Add ${INSTALL_DIR} to your PATH:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
  fi
}

detect_platform
get_latest_tag
download_and_install
