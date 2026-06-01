#!/usr/bin/env bash
#
# syno-cert-push.sh
# Push the certificate that Nginx Proxy Manager (NPM) issues/renews into
# Synology DSM automatically, so services bypassing the proxy (e.g. Synology
# Drive on port 6690) always serve a fresh certificate.
#
# - Locates the cert by domain (SAN), so it survives NPM npm-N index changes
# - Detects renewal via fullchain hash; pushes only when the cert changed
# - 2FA via device_id: register once with --init (enter an OTP), then no OTP
#
# Usage:
#   1) Create the config file (see syno-cert-push.conf.example)
#   2) First run:   ./syno-cert-push.sh --init   (enter OTP once)
#   3) Then cron:   ./syno-cert-push.sh          (automatic, no OTP)
#
# Dependencies: bash, curl, openssl, jq, coreutils (sha256sum)

set -euo pipefail

CONF="${SYNO_CERT_CONF:-/etc/syno-cert-push.conf}"
INIT_MODE=0
[ "${1:-}" = "--init" ] && INIT_MODE=1

# ---------- load config ----------
if [ ! -r "$CONF" ]; then
  echo "ERROR: cannot read config file: $CONF" >&2
  echo "       Set SYNO_CERT_CONF to its path, or create $CONF." >&2
  exit 1
fi
# shellcheck disable=SC1090
. "$CONF"

: "${NPM_LIVE_DIR:?config needs NPM_LIVE_DIR}"
: "${DRIVE_DOMAIN:?config needs DRIVE_DOMAIN}"
: "${SYNO_SCHEME:=https}"
: "${SYNO_HOST:?config needs SYNO_HOST}"
: "${SYNO_PORT:=5001}"
: "${SYNO_USER:?config needs SYNO_USER}"
: "${SYNO_PASS:?config needs SYNO_PASS}"
: "${SYNO_CERT_DESC:?config needs SYNO_CERT_DESC (the description field in the DSM cert list)}"
: "${SYNO_CREATE:=0}"   # 1 = create a new cert if no description matches
: "${STATE_DIR:=/var/lib/syno-cert-push}"
: "${DEVICE_NAME:=CertRenewal}"

BASE="${SYNO_SCHEME}://${SYNO_HOST}:${SYNO_PORT}"
mkdir -p "$STATE_DIR"
DID_FILE="$STATE_DIR/device_id"
HASH_FILE="$STATE_DIR/last_hash"

for bin in curl openssl jq sha256sum; do
  command -v "$bin" >/dev/null 2>&1 || { echo "ERROR: $bin is required." >&2; exit 1; }
done

# --insecure is needed when reaching DSM by internal IP (cert CN mismatch).
CURL=(curl -s --max-time 30)
[ "${SYNO_INSECURE:-1}" = "1" ] && CURL+=(-k)

log() { echo "[$(date '+%F %T')] $*"; }

# ---------- 1. locate NPM cert dir by domain ----------
find_cert_dir() {
  local d san
  for d in "$NPM_LIVE_DIR"/npm-*/; do
    [ -f "${d}fullchain.pem" ] || continue
    san="$(openssl x509 -in "${d}fullchain.pem" -noout -ext subjectAltName 2>/dev/null || true)"
    # match exactly DNS:<domain> to avoid substring false positives
    if printf '%s' "$san" | grep -qE "DNS:${DRIVE_DOMAIN//./\\.}(,|$|[[:space:]])"; then
      printf '%s' "${d%/}"
      return 0
    fi
  done
  return 1
}

CERT_DIR="$(find_cert_dir)" || {
  echo "ERROR: no certificate for $DRIVE_DOMAIN found under $NPM_LIVE_DIR" >&2
  exit 1
}
log "certificate directory: $CERT_DIR"

KEY="$CERT_DIR/privkey.pem"
CERT="$CERT_DIR/cert.pem"        # leaf
CHAIN="$CERT_DIR/chain.pem"      # intermediate
for f in "$KEY" "$CERT" "$CHAIN"; do
  [ -f "$f" ] || { echo "ERROR: missing file: $f" >&2; exit 1; }
done

# ---------- 2. detect renewal (forced in init mode) ----------
CUR_HASH="$(sha256sum "$CERT_DIR/fullchain.pem" | cut -d' ' -f1)"
LAST_HASH="$(cat "$HASH_FILE" 2>/dev/null || true)"
if [ "$INIT_MODE" -eq 0 ] && [ "$CUR_HASH" = "$LAST_HASH" ]; then
  log "certificate unchanged. Nothing to do."
  exit 0
fi
log "certificate changed (or init). Pushing to DSM."

# ---------- 3. DSM login ----------
api_path=""; api_ver=""; SID=""; TOKEN=""
syno_api_info() {
  local info
  info="$("${CURL[@]}" "$BASE/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=SYNO.API.Auth")"
  api_path="$(printf '%s' "$info" | jq -r '.data["SYNO.API.Auth"].path')"
  api_ver="$(printf '%s' "$info" | jq -r '.data["SYNO.API.Auth"].maxVersion')"
  [ -n "$api_path" ] && [ "$api_path" != "null" ] || { echo "ERROR: failed to query API path." >&2; exit 1; }
}

syno_login() {
  local resp err did
  if [ "$INIT_MODE" -eq 1 ]; then
    # first-time registration: enter OTP once -> get device_id
    printf "Enter OTP (2FA) code for Synology user %s: " "$SYNO_USER" >&2
    read -r OTP
    resp="$("${CURL[@]}" "$BASE/webapi/$api_path" \
      --data-urlencode "api=SYNO.API.Auth" \
      --data-urlencode "version=$api_ver" \
      --data-urlencode "method=login" \
      --data-urlencode "format=sid" \
      --data-urlencode "account=$SYNO_USER" \
      --data-urlencode "passwd=$SYNO_PASS" \
      --data-urlencode "enable_syno_token=yes" \
      --data-urlencode "enable_device_token=yes" \
      --data-urlencode "device_name=$DEVICE_NAME" \
      --data-urlencode "otp_code=$OTP")"
    # device_id for api_version > 6, otherwise did
    did="$(printf '%s' "$resp" | jq -r '.data.device_id // .data.did // empty')"
    if [ -n "$did" ]; then
      umask 077; printf '%s' "$did" > "$DID_FILE"
      log "device_id registered -> $DID_FILE (no OTP needed next time)"
    fi
  else
    # automatic: log in with saved device_id, no OTP
    local did_saved
    did_saved="$(cat "$DID_FILE" 2>/dev/null || true)"
    [ -n "$did_saved" ] || { echo "ERROR: no device_id. Run --init first." >&2; exit 1; }
    resp="$("${CURL[@]}" "$BASE/webapi/$api_path" \
      --data-urlencode "api=SYNO.API.Auth" \
      --data-urlencode "version=$api_ver" \
      --data-urlencode "method=login" \
      --data-urlencode "format=sid" \
      --data-urlencode "account=$SYNO_USER" \
      --data-urlencode "passwd=$SYNO_PASS" \
      --data-urlencode "enable_syno_token=yes" \
      --data-urlencode "device_name=$DEVICE_NAME" \
      --data-urlencode "device_id=$did_saved")"
  fi

  err="$(printf '%s' "$resp" | jq -r '.error.code // empty')"
  if [ -n "$err" ]; then
    case "$err" in
      403) echo "ERROR: auth failed (403). device_id may have expired -> run --init again." >&2 ;;
      404) echo "ERROR: wrong OTP code." >&2 ;;
      400) echo "ERROR: wrong account or password." >&2 ;;
      *)   echo "ERROR: login failed (code=$err)." >&2 ;;
    esac
    exit 1
  fi
  SID="$(printf '%s' "$resp" | jq -r '.data.sid // empty')"
  TOKEN="$(printf '%s' "$resp" | jq -r '.data.synotoken // empty')"
  [ -n "$SID" ] && [ -n "$TOKEN" ] || { echo "ERROR: failed to obtain sid/synotoken." >&2; exit 1; }
  log "login ok."
}

syno_logout() {
  [ -n "$SID" ] || return 0
  "${CURL[@]}" "$BASE/webapi/$api_path?api=SYNO.API.Auth&version=$api_ver&method=logout&_sid=$SID" >/dev/null 2>&1 || true
}
trap syno_logout EXIT

syno_api_info
syno_login

# ---------- 4. list certs -> find id/default by description ----------
list_resp="$("${CURL[@]}" -H "X-SYNO-TOKEN: $TOKEN" \
  --data-urlencode "api=SYNO.Core.Certificate.CRT" \
  --data-urlencode "method=list" \
  --data-urlencode "version=1" \
  --data-urlencode "_sid=$SID" \
  "$BASE/webapi/entry.cgi")"

lerr="$(printf '%s' "$list_resp" | jq -r '.error.code // empty')"
if [ -n "$lerr" ]; then
  if [ "$lerr" = "105" ]; then
    echo "ERROR: account is not an administrator (105)." >&2
  else
    echo "ERROR: failed to list certificates (code=$lerr)." >&2
  fi
  exit 1
fi

CERT_ID="$(printf '%s' "$list_resp" | jq -r --arg d "$SYNO_CERT_DESC" \
  '.data.certificates[]? | select(.desc==$d) | .id' | head -n1)"
IS_DEFAULT="$(printf '%s' "$list_resp" | jq -r --arg d "$SYNO_CERT_DESC" \
  '.data.certificates[]? | select(.desc==$d) | .is_default' | head -n1)"

if [ -z "$CERT_ID" ] && [ "$SYNO_CREATE" != "1" ]; then
  echo "ERROR: no certificate with description '$SYNO_CERT_DESC' found." >&2
  echo "       Match SYNO_CERT_DESC to an existing cert, or set SYNO_CREATE=1 to create one." >&2
  exit 1
fi
log "target id='${CERT_ID:-<new>}' default='${IS_DEFAULT:-false}'"

# ---------- 5. import (multipart; curl -F builds the boundary) ----------
IMPORT_ARGS=(
  -H "X-SYNO-TOKEN: $TOKEN"
  -F "key=@$KEY"
  -F "cert=@$CERT"
  -F "inter_cert=@$CHAIN"
  -F "desc=$SYNO_CERT_DESC"
)
[ -n "$CERT_ID" ] && IMPORT_ARGS+=(-F "id=$CERT_ID")
[ "$IS_DEFAULT" = "true" ] && IMPORT_ARGS+=(-F "as_default=true")

imp_resp="$("${CURL[@]}" "${IMPORT_ARGS[@]}" \
  "$BASE/webapi/entry.cgi?api=SYNO.Core.Certificate&method=import&version=1&SynoToken=$TOKEN&_sid=$SID")"

if printf '%s' "$imp_resp" | jq -e '.error' >/dev/null 2>&1; then
  echo "ERROR: certificate import failed: $imp_resp" >&2
  exit 1
fi

# ---------- 6. success: record hash ----------
printf '%s' "$CUR_HASH" > "$HASH_FILE"
if printf '%s' "$imp_resp" | jq -e '.data.restart_httpd==true' >/dev/null 2>&1; then
  log "certificate replaced. DSM HTTP services restarted."
else
  log "certificate replaced."
fi
