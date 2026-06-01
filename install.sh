#!/usr/bin/env bash
#
# install.sh — syno-cert-push 대화형 설치 스크립트
# 의존성 설치 → 설정파일 생성 → device_id 등록(--init) → cron 등록까지 한 번에.
#
# 사용: sudo ./install.sh

set -euo pipefail

BIN_SRC="$(cd "$(dirname "$0")" && pwd)/syno-cert-push.sh"
BIN_DST="/usr/local/bin/syno-cert-push"
CONF_DST="/etc/syno-cert-push.conf"
STATE_DIR="/var/lib/syno-cert-push"

c_b() { printf '\033[1m%s\033[0m' "$1"; }
ask() { local p="$1" d="${2:-}" a; if [ -n "$d" ]; then printf '%s [%s]: ' "$p" "$d" >&2; else printf '%s: ' "$p" >&2; fi; read -r a; printf '%s' "${a:-$d}"; }
ask_secret() { local p="$1" a; printf '%s: ' "$p" >&2; read -rs a; echo >&2; printf '%s' "$a"; }

[ "$(id -u)" -eq 0 ] || { echo "ERROR: root로 실행하세요 (sudo ./install.sh)"; exit 1; }
[ -f "$BIN_SRC" ] || { echo "ERROR: syno-cert-push.sh 를 같은 폴더에서 찾을 수 없습니다."; exit 1; }

echo "=== $(c_b 'syno-cert-push 설치') ==="
echo

# ---------- 1. 의존성 ----------
echo "[1/5] 의존성 확인 (curl, openssl, jq)..."
PM=""
for cand in "apt-get install -y" "dnf install -y" "yum install -y" "apk add" "pacman -S --noconfirm"; do
  command -v "${cand%% *}" >/dev/null 2>&1 && { PM="$cand"; break; }
done
missing=()
for b in curl openssl jq; do command -v "$b" >/dev/null 2>&1 || missing+=("$b"); done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "  설치 필요: ${missing[*]}"
  if [ -n "$PM" ]; then
    command -v apt-get >/dev/null 2>&1 && apt-get update -qq || true
    # shellcheck disable=SC2086
    $PM "${missing[@]}" || true
  fi
  # jq 패키지 설치가 실패하면 정적 바이너리로 폴백
  if ! command -v jq >/dev/null 2>&1; then
    echo "  jq 패키지 설치 실패 → 정적 바이너리 설치 시도"
    arch="$(uname -m)"; case "$arch" in x86_64) jqf=jq-linux-amd64;; aarch64|arm64) jqf=jq-linux-arm64;; *) jqf="";; esac
    [ -n "$jqf" ] && curl -fsSL "https://github.com/jqlang/jq/releases/download/jq-1.7.1/$jqf" -o /usr/local/bin/jq && chmod +x /usr/local/bin/jq
  fi
fi
for b in curl openssl jq; do command -v "$b" >/dev/null 2>&1 || { echo "ERROR: $b 설치 실패. 수동 설치 후 다시 실행하세요."; exit 1; }; done
echo "  OK"
echo

# ---------- 2. 설정 입력 ----------
echo "[2/5] 설정값 입력"

# NPM letsencrypt live 디렉토리 자동 탐지
detect_npm_dir() {
  local cid hostpath c
  if command -v docker >/dev/null 2>&1; then
    cid="$(docker ps --format '{{.ID}} {{.Image}}' 2>/dev/null | grep -iE 'nginx-proxy-manager|jc21' | awk '{print $1}' | head -1 || true)"
    if [ -n "$cid" ]; then
      hostpath="$(docker inspect "$cid" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || true)"
      [ -n "$hostpath" ] && [ -d "$hostpath/letsencrypt/live" ] && { printf '%s' "$hostpath/letsencrypt/live"; return 0; }
    fi
  fi
  for c in /opt/npm/data /opt/*/data /root/*/data /volume*/docker/*/data /home/*/*/data; do
    [ -d "$c/letsencrypt/live" ] && { printf '%s' "$c/letsencrypt/live"; return 0; }
  done
  return 1
}
NPM_GUESS="$(detect_npm_dir || true)"
[ -n "$NPM_GUESS" ] && echo "  NPM 인증서 경로 자동 탐지: $NPM_GUESS"
NPM_LIVE_DIR="$(ask 'NPM letsencrypt live 디렉토리(호스트 경로)' "$NPM_GUESS")"
DRIVE_DOMAIN="$(ask '시놀로지 드라이브 도메인' 'drive.ravnus.com')"
SYNO_HOST="$(ask '시놀로지 내부 IP/호스트')"
SYNO_PORT="$(ask 'DSM HTTPS 포트' '5001')"
SYNO_USER="$(ask 'DSM 관리자 그룹 계정' 'acme')"
SYNO_PASS="$(ask_secret 'DSM 계정 비밀번호')"
SYNO_CERT_DESC="$(ask "시놀로지 인증서 '설명'(교체 대상)" "$DRIVE_DOMAIN")"
SYNO_CREATE="$(ask '일치 인증서 없으면 신규 생성? (1=예,0=아니오)' '0')"
echo

# ---------- 3. 설치 ----------
echo "[3/5] 파일 설치"
install -m 0755 "$BIN_SRC" "$BIN_DST"; echo "  $BIN_DST"
mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
umask 077
cat > "$CONF_DST" <<EOF
# syno-cert-push 설정 (자동 생성)
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

# ---------- 4. device_id 등록 ----------
echo "[4/5] 2FA device_id 등록 (OTP 1회 입력)"
if SYNO_CERT_CONF="$CONF_DST" "$BIN_DST" --init; then
  echo "  등록 성공"
else
  echo "  WARNING: --init 실패. 설정 확인 후 'sudo SYNO_CERT_CONF=$CONF_DST $BIN_DST --init' 재시도하세요."
fi
echo

# ---------- 5. cron ----------
echo "[5/5] cron 등록"
ans="$(ask '매일 04:00 자동 실행 cron을 등록할까요? (y/n)' 'y')"
if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
  CRON_LINE="0 4 * * * SYNO_CERT_CONF=$CONF_DST $BIN_DST >> /var/log/syno-cert-push.log 2>&1"
  ( crontab -l 2>/dev/null | grep -v "$BIN_DST" ; echo "$CRON_LINE" ) | crontab -
  echo "  등록됨: $CRON_LINE"
else
  echo "  건너뜀. 수동 등록 예시:"
  echo "    0 4 * * * SYNO_CERT_CONF=$CONF_DST $BIN_DST >> /var/log/syno-cert-push.log 2>&1"
fi

echo
echo "=== $(c_b '완료') ==="
echo "다음: 시놀로지 제어판 > 보안 > 인증서 > '설정'에서 Synology Drive(6690)를"
echo "      '$SYNO_CERT_DESC' 인증서에 매핑하면 이후 자동 갱신·교체됩니다."
echo "수동 실행 테스트:  sudo SYNO_CERT_CONF=$CONF_DST $BIN_DST"
