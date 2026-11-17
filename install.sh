#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  BESTPRIME DNS — one-line installer for Ubuntu 22.04 / 24.04 (and Debian 12)
#
#    curl -fsSL https://raw.githubusercontent.com/farazghri-cloud/best-dns/main/install.sh | sudo bash
#
#  Options (environment variables, or flags after `bash -s --`):
#    BESTDNS_PANEL_PORT=8080     panel listen port          (default 8080)
#    BESTDNS_PANEL_ADDR=:8080    full panel listen address  (overrides port)
#    BESTDNS_VERSION=v1.0.0      release tag                (default: latest)
#    BESTDNS_REPO=owner/repo     source repository
#    BESTDNS_ALLOW_ALL=1         serve unregistered clients (open resolver)
#    BESTDNS_IP=1.2.3.4          advertised proxy address  (default: auto)
#    BESTDNS_NO_FIREWALL=1       do not touch ufw
#    BESTDNS_LOCAL=1             install a local ./bin/bestdns instead of a release
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO="${BESTDNS_REPO:-farazghri-cloud/best-dns}"
VERSION="${BESTDNS_VERSION:-latest}"
PANEL_ADDR="${BESTDNS_PANEL_ADDR:-:${BESTDNS_PANEL_PORT:-8080}}"
DNS_ADDR="${BESTDNS_DNS_ADDR:-:53}"
PROXY_PORTS="${BESTDNS_PROXY_PORTS:-443}"
STATE_DIR="/var/lib/bestdns"
STATE_FILE="$STATE_DIR/state.json"
BIN="/usr/local/bin/bestdns"
UNIT="/etc/systemd/system/bestdns.service"
SERVICE="bestdns"

C_OK=$'\033[1;32m'; C_WARN=$'\033[1;33m'; C_ERR=$'\033[1;31m'; C_DIM=$'\033[2m'; C_END=$'\033[0m'
step()  { printf '%s▸ %s%s\n' "$C_OK" "$*" "$C_END"; }
info()  { printf '%s  %s%s\n' "$C_DIM" "$*" "$C_END"; }
warn()  { printf '%s! %s%s\n' "$C_WARN" "$*" "$C_END"; }
die()   { printf '%s✗ %s%s\n' "$C_ERR" "$*" "$C_END" >&2; exit 1; }

# flags → env (so both `INSTALL ... | bash -s -- --panel-port 9000` work)
while [ $# -gt 0 ]; do
  case "$1" in
    --panel-port) PANEL_ADDR=":${2:?}"; shift 2 ;;
    --panel-addr) PANEL_ADDR="${2:?}"; shift 2 ;;
    --version)    VERSION="${2:?}"; shift 2 ;;
    --allow-all)  BESTDNS_ALLOW_ALL=1; shift ;;
    --ip)         BESTDNS_IP="${2:?}"; shift 2 ;;
    --no-firewall) BESTDNS_NO_FIREWALL=1; shift ;;
    -h|--help)    sed -n '2,20p' "$0" 2>/dev/null || true; exit 0 ;;
    *)            die "unknown option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root:  curl -fsSL …/install.sh | sudo bash"

if [ -r /etc/os-release ]; then
  . /etc/os-release
  info "system: ${PRETTY_NAME:-unknown}"
fi

case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  armv7l|armv6l) ARCH="armv7" ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
info "architecture: $ARCH"

need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1 (apt-get install -y $2)"; }
need curl curl
need tar tar
need systemctl systemd

# ── 1. fetch the release ─────────────────────────────────────────────────────
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ "${BESTDNS_LOCAL:-0}" = "1" ] && [ -x ./bin/bestdns ]; then
  step "using local binary ./bin/bestdns"
  cp ./bin/bestdns "$TMP/bestdns"
else
  if [ "$VERSION" = "latest" ]; then
    step "resolving the latest release of $REPO"
    RELEASE_JSON="$(curl -fsSL --retry 3 --max-time 30 "https://api.github.com/repos/$REPO/releases/latest" || true)"
    TAG="$(printf '%s' "$RELEASE_JSON" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
    [ -n "$TAG" ] || die "could not reach the GitHub API; set BESTDNS_VERSION=v1.0.0 and retry"
  else
    TAG="$VERSION"
  fi
  info "release: $TAG"

  URL="https://github.com/$REPO/releases/download/$TAG/best-dns-linux-$ARCH.tar.gz"
  step "downloading $URL"
  curl -fsSL --retry 3 --max-time 300 -o "$TMP/pkg.tar.gz" "$URL" \
    || die "download failed — check that the release asset exists for $ARCH"

  if curl -fsSL --retry 1 --max-time 30 -o "$TMP/pkg.sha256" "$URL.sha256" 2>/dev/null; then
    ( cd "$TMP" && sed "s/best-dns-linux-$ARCH.tar.gz/pkg.tar.gz/" pkg.sha256 | sha256sum -c - >/dev/null 2>&1 ) \
      || die "checksum mismatch — refusing to install"
    info "checksum verified"
  else
    warn "no checksum published for this asset"
  fi
  tar -xzf "$TMP/pkg.tar.gz" -C "$TMP" || die "corrupt archive"
  [ -f "$TMP/bestdns" ] || die "archive does not contain the binary"
fi
chmod 755 "$TMP/bestdns"

# ── 2. stop an existing install ──────────────────────────────────────────────
if systemctl list-unit-files 2>/dev/null | grep -q "^$SERVICE.service"; then
  step "stopping the previous installation"
  systemctl stop "$SERVICE" 2>/dev/null || true
fi

# ── 3. user, directories, binary ─────────────────────────────────────────────
step "installing $BIN"
if ! id -u bestdns >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin bestdns 2>/dev/null \
    || useradd -r -d "$STATE_DIR" -s /usr/sbin/nologin bestdns
  info "created system user 'bestdns'"
fi
install -m 0755 "$TMP/bestdns" "$BIN"
mkdir -p "$STATE_DIR"
chown -R bestdns:bestdns "$STATE_DIR"
chmod 700 "$STATE_DIR"
"$BIN" version

# ── 4. systemd unit ──────────────────────────────────────────────────────────
step "writing $UNIT"
EXTRA_ARGS=""
[ -n "${BESTDNS_IP:-}" ] && EXTRA_ARGS="$EXTRA_ARGS -public-ip $BESTDNS_IP"
[ "${BESTDNS_ALLOW_ALL:-0}" = "1" ] && EXTRA_ARGS="$EXTRA_ARGS -allow-all"

cat > "$UNIT" <<UNITEOF
[Unit]
Description=BESTPRIME DNS — smart DNS and SNI relay
Documentation=https://github.com/$REPO
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=bestdns
Group=bestdns
ExecStart=$BIN server -data $STATE_FILE -dns $DNS_ADDR -panel $PANEL_ADDR -proxy-ports $PROXY_PORTS$EXTRA_ARGS
Restart=always
RestartSec=2
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=$STATE_DIR
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNITEOF

# ── 5. kernel tuning (packet loss on busy resolvers) ─────────────────────────
step "applying sysctl tuning"
cat > /etc/sysctl.d/99-bestdns.conf <<'SYSCTLEOF'
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.somaxconn = 4096
net.ipv4.udp_rmem_min = 16384
fs.file-max = 2097152
SYSCTLEOF
sysctl --system >/dev/null 2>&1 || warn "sysctl reload reported an error (usually harmless)"

# ── 6. firewall ──────────────────────────────────────────────────────────────
PANEL_PORT="${PANEL_ADDR##*:}"
if [ "${BESTDNS_NO_FIREWALL:-0}" != "1" ] && command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  step "opening firewall ports"
  ufw allow 53/udp >/dev/null 2>&1 || true
  ufw allow 53/tcp >/dev/null 2>&1 || true
  ufw allow "${PANEL_PORT}/tcp" >/dev/null 2>&1 || true
  IFS=',' read -ra PORTS <<< "$PROXY_PORTS"
  for p in "${PORTS[@]}"; do ufw allow "${p}/tcp" >/dev/null 2>&1 || true; done
fi

# ── 7. start ─────────────────────────────────────────────────────────────────
step "starting the service"
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"

READY=0
for _ in $(seq 1 25); do
  if systemctl is-active --quiet "$SERVICE"; then READY=1; break; fi
  sleep 0.4
done
if [ "$READY" != "1" ]; then
  warn "the service did not start — last log lines:"
  journalctl -u "$SERVICE" -n 20 --no-pager || true
  exit 1
fi

SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$SERVER_IP" ] || SERVER_IP="<server-ip>"
PASSWORD=""
[ -f "$STATE_DIR/state-first-login.txt" ] && \
  PASSWORD="$(grep -o 'password: .*' "$STATE_DIR/state-first-login.txt" | cut -d' ' -f2)"
[ -n "$PASSWORD" ] || PASSWORD="(already set — use: bestdns passwd)"

cat <<SUMMARY

${C_OK}┌───────────────────────────────────────────────────────────────┐
│  BESTPRIME DNS is running                                     │
└───────────────────────────────────────────────────────────────┘${C_END}

  panel      http://${SERVER_IP}:${PANEL_PORT}/
  password   ${PASSWORD}
  dns        ${SERVER_IP}   (دستگاه‌ها را روی این DNS تنظیم کنید)
  relay      ${PROXY_PORTS} (پورت‌های SNI proxy)

  ${C_DIM}state      ${STATE_FILE}
  logs       journalctl -u ${SERVICE} -f
  restart    systemctl restart ${SERVICE}
  login file ${STATE_DIR}/state-first-login.txt  (بعد از تغییر رمز پاکش کنید)${C_END}

  ${C_WARN}مهم:${C_END} در پنل → «مسیرها» دامنه‌های خودت را اضافه کن. تا وقتی مسیری نسازی
  هیچ چیزی از این سرور عبور نمی‌کند و DNS فقط resolve معمولی می‌دهد.

  ${C_WARN}امنیت:${C_END} پنل روی HTTP است. برای دامنه‌دار کردن پنل، README بخش
  «قرار دادن پنل پشت HTTPS» را ببین (Caddy یا Nginx).

SUMMARY
