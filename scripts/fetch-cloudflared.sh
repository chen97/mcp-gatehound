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

TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
[ -n "$TRIPLE" ] || { echo "could not determine the host target triple" >&2; exit 1; }

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

# Tauri resolves a sidecar by stripping the target triple, so the config names the stem only.
if ! grep -q '"externalBin"' "$CONF"; then
  python3 - "$CONF" <<'PY'
import json, sys
path = sys.argv[1]
with open(path) as fh:
    cfg = json.load(fh)
cfg["bundle"]["externalBin"] = ["binaries/cloudflared"]
with open(path, "w") as fh:
    json.dump(cfg, fh, indent=2)
    fh.write("\n")
print("enabled externalBin in", path)
PY
fi

echo "installed $OUT"
echo "MCP Gatehound will now start and stop the tunnel with the app."
