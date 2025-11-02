#!/usr/bin/env bash
set -euo pipefail

# Simple watchdog skeleton for services

SVC_LIST="${SVC_LIST:-haproxy 3proxy}"

check_service() {
  local svc="$1"
  if ! systemctl is-active --quiet "$svc"; then
    echo "[watchdog] $svc inactive, restarting..."
    systemctl restart "$svc" || true
  else
    echo "[watchdog] $svc OK"
  fi
}

for s in ${SVC_LIST}; do
  check_service "$s"
done
