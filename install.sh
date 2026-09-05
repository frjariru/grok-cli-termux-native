#!/data/data/com.termux/files/usr/bin/bash
#
# install.sh — xAI Grok Build CLI (grok), native on Termux (aarch64). No proot.
#
# Grok Build is a statically-linked musl binary that runs directly on the kernel.
# The only thing that fails on Termux is DNS: musl reads /etc/resolv.conf, which
# can't exist on stock Termux (/etc -> /system/etc, read-only). Two paths, both
# native (no proot), auto-selected:
#   • no root → byte-patch that one hardcoded 16-char string -> /sdcard/.grokdns
#     and keep that file populated (zero root, zero reboot).
#   • rooted  → if a systemless module already provides a real /etc/resolv.conf,
#     the PRISTINE binary resolves natively with no patch at all.
# The installed launcher re-checks this every run and self-corrects.
#
set -euo pipefail

say(){ printf '\033[1;32m[grok-native]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[grok-native] WARN\033[0m  %s\n' "$*"; }
die(){ printf '\033[1;31m[grok-native] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
VERSIONS="$HOME_DIR/.grok/versions"
DIR="$HOME_DIR/agents/grok"
DNS="/sdcard/.grokdns"
CHANNEL="${GROK_CHANNEL:-stable}"
PLATFORM="linux-aarch64"
PRIMARY="https://x.ai/cli"
FALLBACK="https://storage.googleapis.com/grok-build-public-artifacts/cli"
RAW="https://raw.githubusercontent.com/Thr45hx/grok-cli-termux-native/main"

# 0) sanity ------------------------------------------------------------------
[ -d "$PREFIX" ] || die "Not a Termux environment."
case "$(uname -m)" in aarch64|arm64) ;; *) die "arm64/aarch64 only (found $(uname -m)).";; esac

# source dir (support curl | bash) ------------------------------------------
SRC="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
need=0
for f in launcher.sh grok-dns.py; do
  [ -f "$SRC/$f" ] || need=1
done
if [ "$need" = 1 ]; then
  command -v curl >/dev/null || die "curl is required to fetch launcher sources."
  SRC="$(mktemp -d)"
  say "Fetching latest launcher.sh and grok-dns.py…"
  for f in launcher.sh grok-dns.py; do
    curl -fsSL "$RAW/$f" -o "$SRC/$f" || die "Failed to download $f"
  done
  say "Launcher scripts downloaded."
fi

# 1) deps --------------------------------------------------------------------
say "Installing base packages (python curl file)…"
pkg update -y >/dev/null 2>&1 || true

# Use --force or wait a bit if another pkg/apt is running (common in Termux)
if ! pkg install -y python curl file >/dev/null 2>&1; then
  say "Another package manager process detected, waiting a moment..."
  sleep 5
  pkg install -y python curl file || die "pkg install failed. Is another 'pkg' or 'apt' running?"
fi

# 2) resolve version ---------------------------------------------------------
VERSION="${1:-}"; BASE="$PRIMARY"
if [ -z "$VERSION" ]; then
  say "Resolving latest $CHANNEL version…"
  VERSION="$(curl -fsSL --max-time 15 "$PRIMARY/$CHANNEL" 2>/dev/null || true)"
  [ -z "$VERSION" ] && { VERSION="$(curl -fsSL --max-time 15 "$FALLBACK/$CHANNEL" 2>/dev/null || true)"; BASE="$FALLBACK"; }
  [ -n "$VERSION" ] || die "could not resolve latest $CHANNEL version."
fi
printf '%s' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+' || die "bad version '$VERSION'."
say "Version: $VERSION"

# 3) download ----------------------------------------------------------------
mkdir -p "$VERSIONS"
tmp="$VERSIONS/$VERSION.tmp"
say "Downloading grok $VERSION ($PLATFORM)…"
if ! curl -fsSL --max-time 600 "$BASE/grok-$VERSION-$PLATFORM" -o "$tmp"; then
  say "Primary failed — trying GCS fallback…"
  curl -fsSL --max-time 600 "$FALLBACK/grok-$VERSION-$PLATFORM" -o "$tmp" || die "download failed."
fi
chmod +x "$tmp"
if command -v file >/dev/null; then
  if file "$tmp" | grep -q "statically linked"; then
    say "Binary is statically linked (good for native Termux)."
  else
    warn "Binary does not appear to be statically linked. Native execution may still work but is not guaranteed."
  fi
else
  warn "Command 'file' not available — skipping static link check."
fi

# 4) DNS mode: pristine-native if a real /etc/resolv.conf exists, else sdcard patch
if [ -s /etc/resolv.conf ] && grep -q '^nameserver' /etc/resolv.conf 2>/dev/null; then
  say "Rooted resolv module detected — keeping pristine binary (native DNS)."
  python3 "$SRC/grok-dns.py" "$tmp" native
else
  say "No /etc/resolv.conf — byte-patching DNS path to $DNS (no-root mode)."
  if [ ! -d "/sdcard" ] || [ ! -w "/sdcard" ]; then
    warn "Storage directory /sdcard not writable. Run: termux-setup-storage"
    # Try to create it anyway (pkg install termux-api may be needed in some cases)
  fi
  grep -qs nameserver "$DNS" 2>/dev/null || printf 'nameserver 8.8.8.8\nnameserver 8.8.4.4\n' > "$DNS" 2>/dev/null || warn "Cannot write $DNS — DNS may fail without storage permission."
  python3 "$SRC/grok-dns.py" "$tmp" sdcard
  if grep -a -q '/etc/resolv.conf' "$tmp"; then
    die "Patch failed: '/etc/resolv.conf' string still present in binary."
  fi
  say "DNS patch applied successfully."
fi

# 5) smoke test (--version needs no DNS) ------------------------------------
say "Running smoke test (--version)…"
smoke="$(mktemp -d)"
if ! HOME="$smoke" timeout -s KILL 25 "$tmp" --version >/dev/null 2>&1; then
  rm -rf "$smoke" "$tmp"
  die "Smoke test failed: binary did not respond to --version (possible corruption or incompatible build)."
fi
rm -rf "$smoke"
say "Smoke test passed."

# 6) promote + retain latest+prev -------------------------------------------
say "Promoting binary to versions store…"
mv "$tmp" "$VERSIONS/$VERSION"
printf '%s\n' "$VERSION" > "$VERSIONS/.verified"

# Keep latest + previous version only (clean old builds)
prev="$(ls -1 "$VERSIONS" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -2 | head -1 || true)"
for old in "$VERSIONS"/*; do
  b="$(basename "$old")"
  case "$b" in .*) continue ;; esac
  [ -f "$old" ] && [ "$b" != "$VERSION" ] && [ "$b" != "$prev" ] && rm -f "$old"
done
say "Version $VERSION is now active (kept latest + previous)."

# 7) launcher + patcher ------------------------------------------------------
mkdir -p "$DIR"
install -m644 "$SRC/grok-dns.py" "$DIR/grok-dns.py"
install -m755 "$SRC/launcher.sh" "$DIR/launcher.sh"
ln -sf "$DIR/launcher.sh" "$PREFIX/bin/grok"

echo
say "✅ Successfully installed grok $VERSION — native on Termux (no proot, no root needed)."
echo
say "Next steps:"
say "  • Authenticate:   export XAI_API_KEY=...   or simply run 'grok'"
say "  • Test:           grok -p \"Hola desde Termux nativo\""
say "  • Update later:   grok update   (then restart the launcher)"
echo
say "The launcher will automatically adopt future updates and re-apply the DNS patch."
echo "Enjoy!"
