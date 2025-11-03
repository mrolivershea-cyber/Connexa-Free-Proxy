#!/usr/bin/env bash
set -euo pipefail

# Connexa Free Proxy installer (MVP)
# - OS: Ubuntu 22.04/24.04 LTS or Debian 12
# - Root required

log() { echo "[install] $*"; }
die() { echo "[install][ERROR] $*" >&2; exit 1; }

require_root() { [[ ${EUID} -eq 0 ]] || die "Run as root (sudo)."; }
detect_os() {
  if [[ -f /etc/os-release ]]; then . /etc/os-release; else die "No /etc/os-release"; fi
  case "${ID}-${VERSION_ID}" in
    ubuntu-22.04|ubuntu-24.04|debian-12) ;;
    *) log "Detected ${ID}-${VERSION_ID}. Proceeding best-effort...";;
  esac
}

install_deps() {
  log "Updating packages..."
  apt-get update -y
  apt-get install -y curl jq ca-certificates gnupg lsb-release software-properties-common \
    tor haproxy build-essential python3 python3-venv python3-pip git netcat-openbsd \
    redis-server ufw nftables rsync
  # 3proxy from source (not available in Ubuntu repos)
  if ! command -v 3proxy >/dev/null 2>&1; then
    log "Installing 3proxy from source..."
    cd /tmp
    wget -q https://github.com/3proxy/3proxy/archive/0.9.4.tar.gz -O 3proxy.tar.gz
    tar xzf 3proxy.tar.gz
    cd 3proxy-0.9.4
    make -f Makefile.Linux
    mkdir -p /usr/local/bin /usr/local/etc/3proxy
    cp bin/3proxy /usr/local/bin/
    chmod +x /usr/local/bin/3proxy
    cd /
    rm -rf /tmp/3proxy-0.9.4 /tmp/3proxy.tar.gz
    log "3proxy installed successfully"
  fi
}

setup_dirs() {
  mkdir -p /etc/connexa /etc/connexa/templates /etc/tor/pool /var/lib/tor/pool /var/log/tor/pool
  mkdir -p /etc/haproxy /etc/3proxy /var/log/3proxy /opt/connexa /var/log/connexa
}

sync_repo_files() {
  # Copy project files into /opt/connexa (assuming running from repo root)
  SRC_DIR="$(cd "$(dirname "$BASH_SOURCE")/.." && pwd)"
  rsync -a --exclude ".git" "$SRC_DIR/" /opt/connexa/
  cp -n /opt/connexa/etc/connexa/config.yaml /etc/connexa/config.yaml || true
}

systemd_units() {
  log "Installing systemd units..."
  cp /opt/connexa/systemd/tor-pool@.service /etc/systemd/system/
  cp /opt/connexa/systemd/tor-rotate.service /etc/systemd/system/
  cp /opt/connexa/systemd/tor-rotate.timer /etc/systemd/system/
  cp /opt/connexa/systemd/geo-resolver.service /etc/systemd/system/
  cp /opt/connexa/systemd/geo-resolver.timer /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable tor-rotate.timer geo-resolver.timer
}

configure_firewall() {
  log "Configuring firewall (nftables/ufw)..."
  ufw allow 22/tcp || true
  # External publish ports will be opened by poolproxyctl expose (respect whitelist)
}

prepare_templates() {
  cp /opt/connexa/etc/haproxy/haproxy.cfg.tmpl /etc/haproxy/haproxy.cfg.tmpl
  cp /opt/connexa/etc/3proxy/3proxy.cfg.tmpl   /etc/3proxy/3proxy.cfg.tmpl
}

python_env() {
  log "Setting up Python venv..."
  python3 -m venv /opt/connexa/.venv
  /opt/connexa/.venv/bin/pip install --upgrade pip
  /opt/connexa/.venv/bin/pip install fastapi uvicorn click pyyaml redis
  ln -sf /opt/connexa/.venv/bin/uvicorn /usr/local/bin/uvicorn
  ln -sf /opt/connexa/cli/poolproxyctl.py /usr/local/bin/poolproxyctl
  chmod +x /usr/local/bin/poolproxyctl
}

post_install() {
  log "Post-install checks..."
  /usr/local/bin/poolproxyctl status || true
  echo
  echo "=== Install complete ==="
  echo "Config: /etc/connexa/config.yaml"
  echo "CLI:    poolproxyctl help"
  echo "API:    uvicorn api.server:app --host 0.0.0.0 --port 8080 (from /opt/connexa)"
}

main() {
  require_root
  detect_os
  install_deps
  setup_dirs
  sync_repo_files
  systemd_units
  prepare_templates
  python_env
  post_install
}
main "$@"
