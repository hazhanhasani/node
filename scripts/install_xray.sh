#!/usr/bin/env sh
set -eu

OS="linux"
ARCH="64"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --os)
      OS="$2"
      shift 2
      ;;
    --arch)
      ARCH="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

case "$OS" in
  linux|freebsd|openbsd|windows|macos) ;;
  darwin) OS="macos" ;;
  *)
    echo "Unsupported Xray OS: $OS" >&2
    exit 1
    ;;
esac

ASSET="Xray-${OS}-${ARCH}.zip"
URL="https://github.com/XTLS/Xray-core/releases/latest/download/${ASSET}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

printf '[BluePanel Node] Downloading %s\n' "$URL"
curl -fL --retry 3 --retry-delay 2 "$URL" -o "$TMP_DIR/xray.zip"
unzip -q "$TMP_DIR/xray.zip" -d "$TMP_DIR/xray"

if [ ! -f "$TMP_DIR/xray/xray" ] && [ ! -f "$TMP_DIR/xray/xray.exe" ]; then
  echo "Xray binary was not found in release archive." >&2
  exit 1
fi

mkdir -p /usr/local/bin /usr/local/share/xray

if [ -f "$TMP_DIR/xray/xray" ]; then
  install -m 0755 "$TMP_DIR/xray/xray" /usr/local/bin/xray
else
  install -m 0755 "$TMP_DIR/xray/xray.exe" /usr/local/bin/xray.exe
fi

for asset in geoip.dat geosite.dat; do
  if [ -f "$TMP_DIR/xray/$asset" ]; then
    install -m 0644 "$TMP_DIR/xray/$asset" "/usr/local/share/xray/$asset"
  fi
done

printf '[BluePanel Node] Xray installed successfully.\n'
