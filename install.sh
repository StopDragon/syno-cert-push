#!/usr/bin/env bash
#
# install.sh - interactive installer for syno-cert-push
# Installs dependencies, writes the config, registers the 2FA device (--init),
# and optionally adds a daily cron job.
#
# Run: sudo ./install.sh

set -euo pipefail

BIN_SRC="$(cd "$(dirname "$0")" && pwd)/syno-cert-push.sh"
BIN_DST="/usr/local/bin/syno-cert-push"
CONF_DST="/etc/syno-cert-push.conf"
STATE_DIR="/var/lib/syno-cert-push"

c_b() { printf '\033[1m%s\033[0m' "$1"; }
ask() { local p="$1" d="${2:-}" a; if [ -n "$d" ]; then printf '%s [%s]: ' "$p" "$d" >&2; else printf '%s: ' "$p" >&2; fi; read -r a; printf '%s' "${a:-$d}"; }
ask_required() { local p="$1" a; while :; do a="$(ask "$p")"; [ -n "$a" ] && { printf '%s' "$a"; return; }; echo "  (required)" >&2; done; }
ask_secret() { local p="$1" a; printf '%s: ' "$p" >&2; read -rs a; echo >&2; printf '%s' "$a"; }

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root (sudo ./install.sh)"; exit 1; }
[ -f "$BIN_SRC" ] || { echo "ERROR: syno-cert-push.sh not found next to install.sh"; exit 1; }

echo "=== $(c_b 'syno-cert-push installer') ==="
echo

# ---------- 1. dependencies ----------
echo "[1/5] Checking dependencies (curl, openssl, jq)..."
PM=""
for cand in "apt-get install -y" "dnf install -y" "yum install -y" "apk add" "pacman -S --noconfirm"; do
  command -v "${cand%% *}" >/dev/null 2>&1 && { PM="$cand"; break; }
done
missing=()
for b in curl openssl jq; do command -v "$b" >/dev/null 2>&1 || missing+=("$b"); done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "  Installing: ${missing[*]}"
  if [ -n "$PM" ]; then
    command -v apt-get >/dev/null 2>&1 && apt-get update -qq || true
    # shellcheck disable=SC2086
    $PM "${missing[@]}" || true
  fi
  if ! command -v jq >/dev/null 2>&1; then
    echo "  jq package install failed -> trying static binary"
    arch="$(uname -m)"; case "$arch" in x86_64) jqf=jq-linux-amd64;; aarch64|arm64) jqf=jq-linux-arm64;; *) jqf="";; esac
    [ -n "$jqf" ] && curl -fsSL "https://github.com/jqlang/jq/releases/download/jq-1.7.1/$jqf" -o /usr/local/bin/jq && chmod +x /usr/local/bin/jq
  fi
fi
for b in curl openssl jq; do command -v "$b" >/dev/null 2>&1 || { echo "ERROR: failed to install $b. Install it manually and re-run."; exit 1; }; done
echo "  OK"
echo

# ---------- 2. configuration ----------
echo "[2/5] Configuration"

# Auto-detect NPM letsencrypt live directory
detect_npm_dir() {
  local cid hostpath c
  if command -v docker >/dev/null 2>&1; then
    cid="$(docker ps --format '{{.ID}} {{.Image}}' 2>/dev/null | grep -iE 'nginx-proxy-manager|jc21' | awk '{print $1}' | head -1 || true)"
    if [ -n "$cid" ]; then
      # NPM standard compose: letsencrypt is a separate /etc/letsencrypt volume
      hostpath="$(docker inspect "$cid" --format '{{range .Mounts}}{{if eq .Destination "/etc/letsencrypt"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || true)"
      [ -n "$hostpath" ] && [ -d "$hostpath/live" ] && { printf '%s' "$hostpath/live"; return 0; }
      # some setups keep it under /data
      hostpath="$(docker inspect "$cid" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || true)"
      [ -n "$hostpath" ] && [ -d "$hostpath/letsencrypt/live" ] && { printf '%s' "$hostpath/letsencrypt/live"; return 0; }
    fi
  fi
  # fall back to scanning common paths (both layouts)
  for c in /opt/npm/letsencrypt /opt/*/letsencrypt /volume*/docker/*/letsencrypt \
           /opt/npm/data/letsencrypt /opt/*/data/letsencrypt /home/*/*/data/letsencrypt; do
    [ -d "$c/live" ] && { printf '%s' "$c/live"; return 0; }
  done
  return 1
}
NPM_GUESS="$(detect_npm_dir || true)"
[ -n "$NPM_GUESS" ] && echo "  Detected NPM cert path: $NPM_GUESS"
NPM_LIVE_DIR="$(ask 'NPM letsencrypt live dir (host path)' "$NPM_GUESS")"
DRIVE_DOMAIN="$(ask_required 'Certificate domain (e.g. drive.example.com)')"
SYNO_HOST="$(ask_required 'Synology host/IP')"
SYNO_PORT="$(ask 'DSM HTTPS port' '5001')"
SYNO_USER="$(ask_required 'DSM account (must be in administrators group)')"
SYNO_PASS="$(ask_secret 'DSM account password')"
SYNO_CERT_DESC="$(ask "DSM certificate description to replace" "$DRIVE_DOMAIN")"
SYNO_CREATE="$(ask 'Create a new cert if no match? (1=yes,0=no)' '0')"
echo

# ---------- 3. install files ----------
echo "[3/5] Installing files"
install -m 0755 "$BIN_SRC" "$BIN_DST"; echo "  $BIN_DST"
mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
umask 077
cat > "$CONF_DST" <<EOF
# syno-cert-push config (auto-generated)
NPM_LIVE_DIR=$NPM_LIVE_DIR
DRIVE_DOMAIN=$DRIVE_DOMAIN
SYNO_SCHEME=https
SYNO_HOST=$SYNO_HOST
SYNO_PORT=$SYNO_PORT
SYNO_INSECURE=1
SYNO_USER=$SYNO_USER
SYNO_PASS=$SYNO_PASS
SYNO_CERT_DESC=$SYNO_CERT_DESC
SYNO_CREATE=$SYNO_CREATE
STATE_DIR=$STATE_DIR
DEVICE_NAME=CertRenewal
EOF
chmod 600 "$CONF_DST"; echo "  $CONF_DST (600)"
echo

# ---------- 4. register device_id ----------
echo "[4/5] Registering 2FA device_id (enter OTP once)"
if SYNO_CERT_CONF="$CONF_DST" "$BIN_DST" --init; then
  echo "  Registered."
else
  echo "  WARNING: --init failed. Fix the config and retry:"
  echo "           sudo SYNO_CERT_CONF=$CONF_DST $BIN_DST --init"
fi
echo

# ---------- 5. cron ----------
echo "[5/5] Cron"
ans="$(ask 'Add a daily cron job at 04:00? (y/n)' 'y')"
if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
  CRON_LINE="0 4 * * * SYNO_CERT_CONF=$CONF_DST $BIN_DST >> /var/log/syno-cert-push.log 2>&1"
  ( crontab -l 2>/dev/null | grep -v "$BIN_DST" ; echo "$CRON_LINE" ) | crontab -
  echo "  Added: $CRON_LINE"
else
  echo "  Skipped. Manual cron example:"
  echo "    0 4 * * * SYNO_CERT_CONF=$CONF_DST $BIN_DST >> /var/log/syno-cert-push.log 2>&1"
fi

echo
echo "=== $(c_b 'Done') ==="
echo "Next: in DSM Control Panel > Security > Certificate > Settings,"
echo "      map Synology Drive (6690) to the '$SYNO_CERT_DESC' certificate once."
echo "Test now:  sudo SYNO_CERT_CONF=$CONF_DST $BIN_DST"
