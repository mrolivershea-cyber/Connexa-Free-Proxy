#!/usr/bin/env bash
set -euo pipefail

# Universal installer for Connexa-Free-Proxy (Debian/Ubuntu)
# Usage (one-liner):
#   curl -fsSL https://raw.githubusercontent.com/mrolivershea-cyber/Connexa-Free-Proxy/main/scripts/install.sh | sudo bash

REPO_URL="https://github.com/mrolivershea-cyber/Connexa-Free-Proxy"
APP_DIR="/opt/Connexa-Free-Proxy"
API_UNIT="/etc/systemd/system/connexa-api.service"
CFG_FILE="/etc/connexa/config.yaml"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[install] Run as root (use sudo)" >&2
    exit 1
  fi
}

pkg_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  # 3proxy may be unavailable in some repos — not fatal
  apt-get install -y git python3-pip haproxy tor jq ufw || true
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
  # permissions for tor data/log
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

install_cli_and_scripts() {
  install -m 0755 "$APP_DIR/cli/poolproxyctl.py" /usr/local/bin/poolproxyctl
  # Service helper scripts
  install -m 0755 "$APP_DIR/scripts/watchdog.sh"      /usr/local/bin/connexa-watchdog || true
  # Rotation helper (fallback inline if missing in repo)
  if [[ -f "$APP_DIR/scripts/rotation.sh" ]]; then
    install -m 0755 "$APP_DIR/scripts/rotation.sh"   /usr/local/bin/connexa-rotation
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
  # TLS fallback & guardrails: install if present, otherwise place stubs to avoid failing timers
  if [[ -f "$APP_DIR/scripts/tls-fallback.sh" ]]; then
    install -m 0755 "$APP_DIR/scripts/tls-fallback.sh" /usr/local/bin/connexa-tls-fallback
  else
    printf '#!/usr/bin/env bash\nexit 0\n' > /usr/local/bin/connexa-tls-fallback && chmod +x /usr/local/bin/connexa-tls-fallback
  fi
  if [[ -f "$APP_DIR/scripts/guardrails.sh" ]]; then
    install -m 0755 "$APP_DIR/scripts/guardrails.sh"   /usr/local/bin/connexa-guardrails
  else
    printf '#!/usr/bin/env bash\nexit 0\n' > /usr/local/bin/connexa-guardrails && chmod +x /usr/local/bin/connexa-guardrails
  fi
}

write_tor_pool_unit() {
  # Ensure a correct tor-pool@.service template exists
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
  # Rotation
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

  # Watchdog
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

  # TLS fallback
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

  # Guardrails
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

  # API service
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
}

bootstrap_services() {
  # init tor pool and expose ports
  poolproxyctl init || true
  poolproxyctl expose || true
}

patch_server_py() {
  # Fix accidental trailing dot at the end of uvicorn.run(...) line if present
  local f="$APP_DIR/api/server.py"
  if [[ -f "$f" ]] && grep -qE 'uvicorn\.run\(.*\)\.[[:space:]]*$' "$f"; then
    sed -i -E 's/(uvicorn\.run\(.*\))\.[[:space:]]*$/\1/' "$f"
    echo "[patch] Fixed trailing dot in api/server.py"
  fi
}

ufw_allow() {
  # Open API port if ufw is installed
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 8080/tcp || true
  fi
}

haproxy_direct_fallback() {
  # If 3proxy is missing, directly map external ports to Tor SOCKS (9050+)
  if command -v 3proxy >/dev/null 2>&1; then
    echo "[haproxy] 3proxy present, skipping direct fallback."
    return 0
  fi
  echo "[haproxy] 3proxy missing, applying direct HAProxy->Tor fallback..."
  eval "$(python3 - <<'PY'
import yaml, sys
c=yaml.safe_load(open("/etc/connexa/config.yaml"))
print("POOL_SIZE=%d" % int(c.get("pool_size",50)))
print("PORT_START=%d" % int((c.get("external") or {}).get("port_start",40000)))
PY
)"
  : "${POOL_SIZE:=50}"
  : "${PORT_START:=40000}"
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
  echo "[haproxy] fallback applied."
}

main() {
  require_root
  pkg_install
  fetch_code
  python_env
  ensure_conf
  install_cli_and_scripts
  write_tor_pool_unit
  patch_server_py
  install_systemd_units
  bootstrap_services
  ufw_allow
  haproxy_direct_fallback
  echo "[install] Done. Health checks:"
  curl -fsS http://127.0.0.1:8080/healthz || true
  curl -fsS http://127.0.0.1:8080/status || true
}

main "$@"