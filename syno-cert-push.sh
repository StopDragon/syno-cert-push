#!/usr/bin/env bash
#
# syno-cert-push.sh
# NPM(Docker)이 발급/갱신하는 인증서를 시놀로지 DSM에 자동으로 밀어넣는다.
# - 인증서 경로는 도메인(SAN)으로 동적 탐색 → npm-N 번호가 바뀌어도 안전
# - 갱신 감지: fullchain 해시 비교 → 바뀌었을 때만 푸시
# - 2FA: device_id 방식(권장). 최초 1회 --init 으로 OTP 등록, 이후 OTP 불필요
#
# 사용법:
#   1) 설정 파일 작성 (syno-cert-push.conf.example 참고)
#   2) 최초 1회:  ./syno-cert-push.sh --init   (OTP 코드 1회 입력)
#   3) 이후 cron: ./syno-cert-push.sh          (자동, OTP 불필요)
#
# 의존성: bash, curl, openssl, jq, coreutils(sha256sum)

set -euo pipefail

CONF="${SYNO_CERT_CONF:-/etc/syno-cert-push.conf}"
INIT_MODE=0
[ "${1:-}" = "--init" ] && INIT_MODE=1

# ---------- 설정 로드 ----------
if [ ! -r "$CONF" ]; then
  echo "ERROR: 설정 파일을 읽을 수 없습니다: $CONF" >&2
  echo "       SYNO_CERT_CONF 환경변수로 경로를 지정하거나 $CONF 를 생성하세요." >&2
  exit 1
fi
# shellcheck disable=SC1090
. "$CONF"

: "${NPM_LIVE_DIR:?conf에 NPM_LIVE_DIR 필요}"
: "${DRIVE_DOMAIN:?conf에 DRIVE_DOMAIN 필요}"
: "${SYNO_SCHEME:=https}"
: "${SYNO_HOST:?conf에 SYNO_HOST 필요}"
: "${SYNO_PORT:=5001}"
: "${SYNO_USER:?conf에 SYNO_USER 필요}"
: "${SYNO_PASS:?conf에 SYNO_PASS 필요}"
: "${SYNO_CERT_DESC:?conf에 SYNO_CERT_DESC 필요 (시놀로지 인증서 목록의 '설명')}"
: "${SYNO_CREATE:=0}"   # 1이면 설명이 일치하는 인증서가 없을 때 신규 생성
: "${STATE_DIR:=/var/lib/syno-cert-push}"
: "${DEVICE_NAME:=CertRenewal}"

BASE="${SYNO_SCHEME}://${SYNO_HOST}:${SYNO_PORT}"
mkdir -p "$STATE_DIR"
DID_FILE="$STATE_DIR/device_id"
HASH_FILE="$STATE_DIR/last_hash"

for bin in curl openssl jq sha256sum; do
  command -v "$bin" >/dev/null 2>&1 || { echo "ERROR: $bin 가 필요합니다." >&2; exit 1; }
done

# curl: --insecure 는 내부 IP의 https에 CN이 안 맞을 때 필요. conf에서 끌 수 있음.
CURL=(curl -s --max-time 30)
[ "${SYNO_INSECURE:-1}" = "1" ] && CURL+=(-k)

log() { echo "[$(date '+%F %T')] $*"; }

# ---------- 1. NPM 인증서 경로 동적 탐색 ----------
find_cert_dir() {
  local d san
  for d in "$NPM_LIVE_DIR"/npm-*/; do
    [ -f "${d}fullchain.pem" ] || continue
    san="$(openssl x509 -in "${d}fullchain.pem" -noout -ext subjectAltName 2>/dev/null || true)"
    # 정확히 DNS:<도메인> 으로 매칭 (부분문자열 오탐 방지)
    if printf '%s' "$san" | grep -qE "DNS:${DRIVE_DOMAIN//./\\.}(,|$|[[:space:]])"; then
      printf '%s' "${d%/}"
      return 0
    fi
  done
  return 1
}

CERT_DIR="$(find_cert_dir)" || {
  echo "ERROR: $NPM_LIVE_DIR 아래에서 $DRIVE_DOMAIN 인증서를 찾지 못했습니다." >&2
  exit 1
}
log "인증서 디렉토리: $CERT_DIR"

KEY="$CERT_DIR/privkey.pem"
CERT="$CERT_DIR/cert.pem"        # leaf
CHAIN="$CERT_DIR/chain.pem"      # intermediate
for f in "$KEY" "$CERT" "$CHAIN"; do
  [ -f "$f" ] || { echo "ERROR: 파일 없음: $f" >&2; exit 1; }
done

# ---------- 2. 갱신 감지 (init 모드에서는 강제 푸시) ----------
CUR_HASH="$(sha256sum "$CERT_DIR/fullchain.pem" | cut -d' ' -f1)"
LAST_HASH="$(cat "$HASH_FILE" 2>/dev/null || true)"
if [ "$INIT_MODE" -eq 0 ] && [ "$CUR_HASH" = "$LAST_HASH" ]; then
  log "인증서 변경 없음. 종료."
  exit 0
fi
log "인증서 변경 감지(또는 init). DSM에 푸시합니다."

# ---------- 3. DSM 로그인 ----------
api_path=""; api_ver=""; SID=""; TOKEN=""
syno_api_info() {
  local info
  info="$("${CURL[@]}" "$BASE/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=SYNO.API.Auth")"
  api_path="$(printf '%s' "$info" | jq -r '.data["SYNO.API.Auth"].path')"
  api_ver="$(printf '%s' "$info" | jq -r '.data["SYNO.API.Auth"].maxVersion')"
  [ -n "$api_path" ] && [ "$api_path" != "null" ] || { echo "ERROR: API 경로 조회 실패." >&2; exit 1; }
}

syno_login() {
  local resp err did
  if [ "$INIT_MODE" -eq 1 ]; then
    # 최초 등록: OTP 1회 입력 → device_id 발급
    printf "시놀로지 '%s' 계정의 OTP(2FA) 코드 입력: " "$SYNO_USER" >&2
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
    # api_version > 6 이면 device_id, 아니면 did
    did="$(printf '%s' "$resp" | jq -r '.data.device_id // .data.did // empty')"
    if [ -n "$did" ]; then
      umask 077; printf '%s' "$did" > "$DID_FILE"
      log "device_id 등록 완료 → $DID_FILE (다음부터 OTP 불필요)"
    fi
  else
    # 자동: 저장된 device_id로 OTP 없이 로그인
    local did_saved
    did_saved="$(cat "$DID_FILE" 2>/dev/null || true)"
    [ -n "$did_saved" ] || { echo "ERROR: device_id 없음. 먼저 --init 으로 등록하세요." >&2; exit 1; }
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
      403) echo "ERROR: 인증 실패(403). device_id 만료 가능 → --init 으로 재등록 필요." >&2 ;;
      404) echo "ERROR: OTP 코드가 틀렸습니다." >&2 ;;
      400) echo "ERROR: 계정 또는 비밀번호 오류." >&2 ;;
      *)   echo "ERROR: 로그인 실패 (code=$err)." >&2 ;;
    esac
    exit 1
  fi
  SID="$(printf '%s' "$resp" | jq -r '.data.sid // empty')"
  TOKEN="$(printf '%s' "$resp" | jq -r '.data.synotoken // empty')"
  [ -n "$SID" ] && [ -n "$TOKEN" ] || { echo "ERROR: sid/synotoken 획득 실패." >&2; exit 1; }
  log "로그인 성공."
}

syno_logout() {
  [ -n "$SID" ] || return 0
  "${CURL[@]}" "$BASE/webapi/$api_path?api=SYNO.API.Auth&version=$api_ver&method=logout&_sid=$SID" >/dev/null 2>&1 || true
}
trap syno_logout EXIT

syno_api_info
syno_login

# ---------- 4. 인증서 목록 → 설명으로 id/default 찾기 ----------
list_resp="$("${CURL[@]}" -H "X-SYNO-TOKEN: $TOKEN" \
  --data-urlencode "api=SYNO.Core.Certificate.CRT" \
  --data-urlencode "method=list" \
  --data-urlencode "version=1" \
  --data-urlencode "_sid=$SID" \
  "$BASE/webapi/entry.cgi")"

lerr="$(printf '%s' "$list_resp" | jq -r '.error.code // empty')"
if [ -n "$lerr" ]; then
  [ "$lerr" = "105" ] && echo "ERROR: 계정에 관리자 권한이 없습니다(105)." >&2 \
                      || echo "ERROR: 인증서 목록 조회 실패 (code=$lerr)." >&2
  exit 1
fi

CERT_ID="$(printf '%s' "$list_resp" | jq -r --arg d "$SYNO_CERT_DESC" \
  '.data.certificates[]? | select(.desc==$d) | .id' | head -n1)"
IS_DEFAULT="$(printf '%s' "$list_resp" | jq -r --arg d "$SYNO_CERT_DESC" \
  '.data.certificates[]? | select(.desc==$d) | .is_default' | head -n1)"

if [ -z "$CERT_ID" ] && [ "$SYNO_CREATE" != "1" ]; then
  echo "ERROR: '$SYNO_CERT_DESC' 설명의 인증서를 찾지 못했습니다." >&2
  echo "       기존 인증서 설명을 conf의 SYNO_CERT_DESC와 맞추거나, 신규 생성하려면 SYNO_CREATE=1 로 설정하세요." >&2
  exit 1
fi
log "교체 대상 id='${CERT_ID:-<신규>}' default='${IS_DEFAULT:-false}'"

# ---------- 5. import (multipart, curl -F가 boundary 자동 구성) ----------
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
  echo "ERROR: 인증서 import 실패: $imp_resp" >&2
  exit 1
fi

# ---------- 6. 성공: 해시 기록 ----------
printf '%s' "$CUR_HASH" > "$HASH_FILE"
if printf '%s' "$imp_resp" | jq -e '.data.restart_httpd==true' >/dev/null 2>&1; then
  log "인증서 교체 완료. DSM HTTP 서비스 재시작됨."
else
  log "인증서 교체 완료."
fi
