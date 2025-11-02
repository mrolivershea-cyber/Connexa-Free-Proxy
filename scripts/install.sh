#!/usr/bin/env bash
set -euo pipefail

# Universal installer for Connexa-Free-Proxy (Debian/Ubuntu)
# Usage (one-liner):
#   curl -fsSL https://raw.githubusercontent.com/mrolivershea-cyber/Connexa-Free-Proxy/main/scripts/install.sh | sudo bash

REPO_URL="https://github.com/mrolivershea-cyber/Connexa-Free-Proxy"
APP_DIR="/opt/Connexa-Free-Proxy"
API_UNIT="/etc/systemd/system/connexa-api.service"
CFG_FILE="/etc/connexa/config.yaml"
ADMIN_CREDS_FILE="/etc/connexa/haproxy-admin"
STATS_PORT=8081
THREEPROXY_VERSION="0.9.4"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[install] Run as root (use sudo)" >&2
    exit 1
  fi
}

pkg_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  # base deps
  apt-get install -y git python3-pip haproxy tor jq ufw curl ca-certificates openssl build-essential make gcc wget || true
  # try 3proxy via apt (may be absent)
  apt-get install -y 3proxy || true
}

fetch_code() {
  mkdir -p "$(dirname "$APP_DIR")"
  if [[ -d "$APP_DIR/.git" ]]; then
    git -C "$APP_DIR" pull --ff-only
  else
    git clone "$REPO_URL" "$APP_DIR"
  fi
}

python_env() {
  python3 -m pip install --upgrade pip
  python3 -m pip install "uvicorn[standard]" fastapi pyyaml click
}

ensure_conf() {
  mkdir -p /etc/connexa /etc/haproxy /etc/3proxy /etc/tor/pool /var/lib/tor/pool /var/log/tor/pool
  chown -R debian-tor:debian-tor /var/lib/tor/pool || true
  chown -R debian-tor:debian-tor /var/log/tor/pool || true
  if [[ ! -f "$CFG_FILE" ]]; then
    if [[ -f "$APP_DIR/config/config.sample.yaml" ]]; then
      cp "$APP_DIR/config/config.sample.yaml" "$CFG_FILE"
    else
      cat >"$CFG_FILE" <<'YAML'
pool_size: 50
external:
  host: 127.0.0.1
  port_start: 40000
  protocol_default: socks5
  access_mode_default: direct
rotation:
  interval: 5m
security:
  whitelist_direct:
    - 127.0.0.1
tls:
  mode: disabled
  cert_path: /etc/ssl/certs/connexa.crt
  key_path: /etc/ssl/private/connexa.key
network:
  mac_persist: {}
YAML
    fi
  fi
}

get_public_ipv4() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++){if($i=="src"){print $(i+1); exit}}}' || true
}

update_external_host_if_needed() {
  local PUBIP
  PUBIP=$(get_public_ipv4)
  if [[ -z "${PUBIP:-}" ]]; then PUBIP=$(hostname -I 2>/dev/null | awk '{print $1}'); fi
  if [[ -z "${PUBIP:-}" ]]; then echo "[host] cannot detect public IPv4, skipping"; return 0; fi
  python3 - "$PUBIP" <<'PY'
import sys, yaml
cfg_path = "/etc/connexa/config.yaml"
with open(cfg_path,'r') as f: c = yaml.safe_load(f)
external = c.get('external') or {}
host = (external.get('host') or '').strip()
new_host = sys.argv[1]
if host in ('','127.0.0.1','0.0.0.0','localhost'):
    external['host'] = new_host
    c['external'] = external
    with open(cfg_path,'w') as f:
        yaml.safe_dump(c, f, sort_keys=False, allow_unicode=True)
    print(f"[host] external.host set to {new_host}")
else:
    print(f"[host] external.host kept as {host}")
PY
}

install_cli_and_scripts() {
  install -m 0755 "$APP_DIR/cli/poolproxyctl.py" /usr/local/bin/poolproxyctl
  install -m 0755 "$APP_DIR/scripts/watchdog.sh" /usr/local/bin/connexa-watchdog || true
  if [[ -f "$APP_DIR/scripts/rotation.sh" ]]; then
    install -m 0755 "$APP_DIR/scripts/rotation.sh" /usr/local/bin/connexa-rotation
  else
    cat >/usr/local/bin/connexa-rotation <<'SH'
#!/usr/bin/env bash
set -euo pipefail
POOL_SIZE=$(python3 - <<'PY'
import yaml
c=yaml.safe_load(open("/etc/connexa/config.yaml"))
print(int(c.get("pool_size",50)))
PY
)
for ((i=1;i<=POOL_SIZE;i++)); do systemctl restart "tor-pool@${i}.service" || true; done
echo "[rotation] done."
SH
    chmod +x /usr/local/bin/connexa-rotation
  fi
  if [[ -f "$APP_DIR/scripts/tls-fallback.sh" ]]; then
    install -m 0755 "$APP_DIR/scripts/tls-fallback.sh" /usr/local/bin/connexa-tls-fallback
  else
    printf '#!/usr/bin/env bash\nexit 0\n' > /usr/local/bin/connexa-tls-fallback && chmod +x /usr/local/bin/connexa-tls-fallback
  fi
  if [[ -f "$APP_DIR/scripts/guardrails.sh" ]]; then
    install -m 0755 "$APP_DIR/scripts/guardrails.sh" /usr/local/bin/connexa-guardrails
  else
    printf '#!/usr/bin/env bash\nexit 0\n' > /usr/local/bin/connexa-guardrails && chmod +x /usr/local/bin/connexa-guardrails
  fi
}

write_tor_pool_unit() {
  cat >/etc/systemd/system/tor-pool@.service <<'UNIT'
[Unit]
Description=Tor pool node %i
After=network-online.target
Wants=network-online.target

[Service]
User=debian-tor
Group=debian-tor
ExecStart=/usr/bin/tor -f /etc/tor/pool/torrc-%i
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
}

install_systemd_units() {
  cat >/etc/systemd/system/connexa-rotation.service <<'UNIT'
[Unit]
Description=Connexa rotation job (Tor pool soft rotation)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/connexa-rotation
UNIT
  cat >/etc/systemd/system/connexa-rotation.timer <<'UNIT'
[Unit]
Description=Connexa rotation timer
[Timer]
OnUnitActiveSec=5m
Persistent=true
Unit=connexa-rotation.service
[Install]
WantedBy=timers.target
UNIT

  cat >/etc/systemd/system/connexa-watchdog.service <<'UNIT'
[Unit]
Description=Connexa watchdog (haproxy/3proxy)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/connexa-watchdog
UNIT
  cat >/etc/systemd/system/connexa-watchdog.timer <<'UNIT'
[Unit]
Description=Connexa watchdog periodic tick
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Persistent=true
Unit=connexa-watchdog.service
[Install]
WantedBy=timers.target
UNIT

  cat >/etc/systemd/system/connexa-tls-fallback.service <<'UNIT'
[Unit]
Description=Connexa TLS fallback (auto-disable TLS on certificate errors)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/connexa-tls-fallback
UNIT
  cat >/etc/systemd/system/connexa-tls-fallback.timer <<'UNIT'
[Unit]
Description=Connexa TLS fallback periodic check
[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
Persistent=true
Unit=connexa-tls-fallback.service
[Install]
WantedBy=timers.target
UNIT

  cat >/etc/systemd/system/connexa-guardrails.service <<'UNIT'
[Unit]
Description=Connexa guardrails (resource usage enforcement)
[Service]
Type=oneshot
Environment=MAX_MEM_MB_HAPROXY=512
Environment=MAX_CPU_PCT_HAPROXY=250
Environment=MAX_MEM_MB_3PROXY=256
Environment=MAX_CPU_PCT_3PROXY=200
Environment=MAX_MEM_MB_TOR=1024
Environment=MAX_CPU_PCT_TOR=300
ExecStart=/usr/local/bin/connexa-guardrails
UNIT
  cat >/etc/systemd/system/connexa-guardrails.timer <<'UNIT'
[Unit]
Description=Connexa guardrails periodic check
[Timer]
OnBootSec=1min
OnUnitActiveSec=2min
Persistent=true
Unit=connexa-guardrails.service
[Install]
WantedBy=timers.target
UNIT

  cat >"$API_UNIT" <<'UNIT'
[Unit]
Description=Connexa Free Proxy API
After=network-online.target
Wants=network-online.target
[Service]
User=root
WorkingDirectory=/opt/Connexa-Free-Proxy
ExecStart=/usr/bin/python3 -m uvicorn api.server:app --host 0.0.0.0 --port 8080
Restart=always
[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable --now connexa-rotation.timer connexa-watchdog.timer connexa-tls-fallback.timer connexa-guardrails.timer
  systemctl enable --now connexa-api
  systemctl enable --now haproxy || true
}

install_3proxy_from_source() {
  if command -v 3proxy >/dev/null 2>&1; then
    echo "[3proxy] already present"
    return 0
  fi
  echo "[3proxy] building from source v${THREEPROXY_VERSION}..."
  tmpd=$(mktemp -d); trap 'rm -rf "$tmpd"' EXIT
  ( cd "$tmpd" && \
    wget -qO 3proxy.tar.gz https://github.com/z3APA3A/3proxy/archive/refs/tags/${THREEPROXY_VERSION}.tar.gz && \
    tar -xzf 3proxy.tar.gz && cd 3proxy-* && \
    make -f Makefile.Linux >/dev/null 2>&1 || make -f Makefile.Linux ) || true
  # install binary
  if [[ -f "$tmpd"/3proxy-*/src/3proxy ]]; then
    install -m 0755 "$tmpd"/3proxy-*/src/3proxy /usr/local/sbin/3proxy
  elif [[ -f "$tmpd"/3proxy-*/bin/3proxy ]]; then
    install -m 0755 "$tmpd"/3proxy-*/bin/3proxy /usr/local/sbin/3proxy
  fi
  if ! command -v 3proxy >/dev/null 2>&1; then
    echo "[3proxy] build failed, will use HAProxy->Tor fallback"
    return 0
  fi
  mkdir -p /etc/3proxy /var/log/3proxy
  cat >/etc/systemd/system/3proxy.service <<'UNIT'
[Unit]
Description=3proxy tiny proxy server
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/sbin/3proxy /etc/3proxy/3proxy.cfg
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now 3proxy || true
  echo "[3proxy] installed and service enabled"
}

wait_for_tor_pool() {
  for i in {1..30}; do
    systemctl is-active --quiet tor-pool@1.service && { echo "[tor] pool is active"; return 0; }
    sleep 1
  done
  echo "[tor] pool not active yet (continuing)"
}

patch_server_py() {
  local f="$APP_DIR/api/server.py"
  if [[ -f "$f" ]] && grep -qE 'uvicorn\.run\(.*\)\.[[:space:]]*$' "$f"; then
    sed -i -E 's/(uvicorn\.run\(.*\))\.[[:space:]]*$/\1/' "$f"
    echo "[patch] Fixed trailing dot in api/server.py"
  fi
}

ufw_allow() {
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 8080/tcp || true
    ufw allow ${STATS_PORT}/tcp || true
    eval "$(python3 - <<'PY'
import yaml
c=yaml.safe_load(open('/etc/connexa/config.yaml'))
ps=int(c.get('pool_size',50))
start=int((c.get('external') or {}).get('port_start',40000))
print(f'POOL_SIZE={{ps}}')
print(f'PORT_START={{start}}')
PY
)"
    if [[ -n "${PORT_START:-}" && -n "${POOL_SIZE:-}" ]]; then
      local end=$((PORT_START + POOL_SIZE - 1))
      ufw allow ${PORT_START}:${end}/tcp || true
    fi
  fi
}

ensure_admin_creds() {
  if [[ -f "$ADMIN_CREDS_FILE" ]]; then return 0; fi
  local pass
  pass=$(openssl rand -base64 12 2>/dev/null || head -c16 /dev/urandom | base64)
  echo "admin:${pass}" > "$ADMIN_CREDS_FILE"
  chmod 600 "$ADMIN_CREDS_FILE"
  echo "[admin] HAProxy stats credentials saved to $ADMIN_CREDS_FILE"
}

haproxy_direct_fallback() {
  # If 3proxy missing or inactive, directly map external ports to Tor SOCKS (9050+) and enable stats
  local active
  active=$(systemctl is-active 3proxy 2>/dev/null || true)
  if command -v 3proxy >/dev/null 2>&1 && [[ "$active" == "active" ]]; then
    echo "[haproxy] 3proxy active, skipping direct fallback."
    return 0
  fi
  ensure_admin_creds
  local CREDS USER PASS
  CREDS=$(cat "$ADMIN_CREDS_FILE"); USER="${CREDS%%:*}"; PASS="${CREDS#*:}"
  echo "[haproxy] applying direct HAProxy->Tor fallback..."
  eval "$(python3 - <<'PY'
import yaml
c=yaml.safe_load(open('/etc/connexa/config.yaml'))
print('POOL_SIZE=%d' % int(c.get('pool_size',50)))
print('PORT_START=%d' % int((c.get('external') or {}).get('port_start',40000)))
print('HOST=%s' % ((c.get('external') or {}).get('host') or ''))
PY
)"
  : "${POOL_SIZE:=50}"; : "${PORT_START:=40000}"; : "${HOST:=}"
  {
    echo "global"
    echo "    daemon"
    echo "    maxconn 20480"
    echo ""
    echo "defaults"
    echo "    mode tcp"
    echo "    timeout connect 5s"
    echo "    timeout client  1m"
    echo "    timeout server  1m"
    echo ""
    echo "listen stats"
    echo "    bind 0.0.0.0:${STATS_PORT}"
    echo "    stats enable"
    echo "    stats uri /"
    echo "    stats refresh 10s"
    echo "    stats auth ${USER}:${PASS}"
    echo ""
    for ((i=0; i<POOL_SIZE; i++)); do
      ext=$((PORT_START+i))
      tor=$((9050+i))
      echo "frontend fe_${ext}"
      echo "    bind *:${ext}"
      echo "    default_backend be_${tor}"
      echo ""
      echo "backend be_${tor}"
      echo "    server s1 127.0.0.1:${tor} check"
      echo ""
    done
  } > /etc/haproxy/haproxy.cfg
  systemctl restart haproxy || true
  if [[ -n "${HOST}" ]]; then
    echo "[haproxy] stats: http://${HOST}:${STATS_PORT}/ (credentials in $ADMIN_CREDS_FILE)"
  else
    echo "[haproxy] stats enabled on port ${STATS_PORT} (credentials in $ADMIN_CREDS_FILE)"
  fi
  echo "[haproxy] fallback applied."
}

main() {
  require_root
  pkg_install
  fetch_code
  python_env
  ensure_conf
  update_external_host_if_needed
  install_cli_and_scripts
  write_tor_pool_unit
  patch_server_py
  install_systemd_units
  poolproxyctl init || true
  wait_for_tor_pool || true
  install_3proxy_from_source || true
  poolproxyctl expose || true
  haproxy_direct_fallback
  ufw_allow
  echo "[install] Done. Health checks:"
  curl -fsS http://127.0.0.1:8080/healthz || true
  curl -fsS http://127.0.0.1:8080/status || true
}

main "$@"