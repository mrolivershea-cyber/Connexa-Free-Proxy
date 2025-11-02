#!/usr/bin/env bash
set -euo pipefail

# Skeleton for multi-uplink/SNAT operations.

ensure_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[network] need root" >&2
    exit 1
  fi
}

uplink_add() {
  local name="$1" dev="$2" gw="$3" metric="${4:-100}" table_id="${5:-101}"
  echo "[network] uplink add name=${name} dev=${dev} gw=${gw} metric=${metric} table=${table_id}"
  # ip route add default via "${gw}" dev "${dev}" metric "${metric}" table "${table_id}" || true
  # ip rule add fwmark "${table_id}" table "${table_id}" || true
}

uplink_del() {
  local name="$1" table_id="${2:-101}"
  echo "[network] uplink del name=${name} table=${table_id}"
  # ip rule del table "${table_id}" || true
  # ip route flush table "${table_id}" || true
}

case "${1:-}" in
  add) shift; ensure_root; uplink_add "$@";;
  del) shift; ensure_root; uplink_del "$@";;
  *) echo "usage: $0 {add|del} ..."; exit 2;;
 esac
