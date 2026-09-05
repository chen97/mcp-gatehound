#!/usr/bin/env sh
# Fetch cloudflared into the Tauri sidecar slot and enable it in tauri.conf.json.
#
# The binary is ~40 MB, so it is not committed. Run this once before building an installer
# that should carry its own tunnel; without it MCP Gatehound still runs, serving on loopback
# only, and says so in the log.
#
#   sh scripts/fetch-cloudflared.sh [version]

set -eu

VERSION="${1:-latest}"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DEST="$ROOT/crates/gatehound-app/binaries"
CONF="$ROOT/crates/gatehound-app/tauri.conf.json"

# Tauri names a sidecar with the Rust target triple, so that is what the file has to be called.
# rustc knows it authoritatively, but this script only downloads a binary — needing a Rust
# toolchain to do that would make it fail before you have one, which is exactly when you run it.
if [ -n "${TRIPLE:-}" ]; then
  :
elif command -v rustc >/dev/null 2>&1; then
  TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
else
  case "$(uname -s)" in
    Darwin) OS=apple-darwin ;;
    Linux)  OS=unknown-linux-gnu ;;
    MINGW*|MSYS*|CYGWIN*) OS=pc-windows-msvc ;;
    *) OS="" ;;
  esac
  case "$(uname -m)" in
    arm64|aarch64) ARCH=aarch64 ;;
    x86_64|amd64)  ARCH=x86_64 ;;
    *) ARCH="" ;;
  esac
  [ -n "$OS" ] && [ -n "$ARCH" ] && TRIPLE="$ARCH-$OS" || TRIPLE=""
fi

if [ -z "${TRIPLE:-}" ]; then
  echo "could not determine the host target triple from $(uname -s)/$(uname -m)" >&2
  echo "pass it explicitly:  TRIPLE=aarch64-apple-darwin sh scripts/fetch-cloudflared.sh" >&2
  exit 1
fi
echo "host target: $TRIPLE"

case "$TRIPLE" in
  x86_64-apple-darwin)          ASSET=cloudflared-darwin-amd64.tgz ;;
  aarch64-apple-darwin)         ASSET=cloudflared-darwin-arm64.tgz ;;
  x86_64-unknown-linux-gnu)     ASSET=cloudflared-linux-amd64 ;;
  aarch64-unknown-linux-gnu)    ASSET=cloudflared-linux-arm64 ;;
  x86_64-pc-windows-msvc)       ASSET=cloudflared-windows-amd64.exe ;;
  *) echo "no cloudflared build is published for $TRIPLE" >&2; exit 1 ;;
esac

case "$TRIPLE" in *windows*) EXT=".exe" ;; *) EXT="" ;; esac
OUT="$DEST/cloudflared-$TRIPLE$EXT"

if [ "$VERSION" = latest ]; then
  URL="https://github.com/cloudflare/cloudflared/releases/latest/download/$ASSET"
else
  URL="https://github.com/cloudflare/cloudflared/releases/download/$VERSION/$ASSET"
fi

mkdir -p "$DEST"
echo "fetching $URL"
case "$ASSET" in
  *.tgz)
    TMP="$(mktemp -d)"
    curl -fsSL "$URL" -o "$TMP/cf.tgz"
    tar -xzf "$TMP/cf.tgz" -C "$TMP"
    mv "$TMP/cloudflared" "$OUT"
    rm -rf "$TMP"
    ;;
  *)
    curl -fsSL "$URL" -o "$OUT"
    ;;
esac
chmod +x "$OUT"

# Tauri resolves a sidecar by stripping the target triple, so the overlay names the stem only.
#
# This goes in a separate, untracked config rather than into tauri.conf.json. Editing a tracked
# file here would put every user in conflict on their next `git pull`, and would also commit a
# reference to a 40 MB binary that is not in the repository — so a fresh clone would fail to
# build. Tauri merges the overlay when it is passed with --config.
OVERLAY="$ROOT/crates/gatehound-app/tauri.sidecar.conf.json"
cat > "$OVERLAY" <<JSON
{
  "bundle": {
    "externalBin": ["binaries/cloudflared"]
  }
}
JSON

echo "installed $OUT"
echo "wrote $OVERLAY"
echo
echo "Build the app with the tunnel inside it:"
echo "  cd crates/gatehound-app && cargo tauri build --config tauri.sidecar.conf.json"
