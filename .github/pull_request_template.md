## What’s included

- Installer
  - scripts/connexa-free-proxy.sh (Ubuntu 22.04/24.04 LTS, Debian 12)
- Config (defaults)
  - etc/connexa/config.yaml (POOL_SIZE=50, rotation 5m, Safety=Balanced, Auto Snapshot+Rollback=On, Shadow‑canary=Off, Auto‑Tune low‑risk=Off)
- Proxies and templates
  - etc/haproxy/haproxy.cfg.tmpl
  - etc/3proxy/3proxy.cfg.tmpl
- Systemd
  - systemd/tor-pool@.service
  - systemd/tor-rotate.service, systemd/tor-rotate.timer
  - systemd/geo-resolver.service, systemd/geo-resolver.timer
- CLI (MVP)
  - cli/poolproxyctl.py (status, rotate-interval, selftest placeholder, expose/hide placeholder)
- API (MVP)
  - api/server.py (/healthz, /status), api/geo_worker.py (placeholder)
- Docs
  - README.md
  - docs/Connexa-Free-Proxy_Functions-and-Controls.txt
  - LICENSE, .gitignore

## Defaults and behavior

- Pool: 50 nodes (scalable to 500)
- External protocol: SOCKS5 (both: auth + direct via whitelist)
- Rotation: 5m (systemd timer)
- Safety: Balanced; Auto Snapshot+Rollback: On; Shadow‑canary default: Off; Auto‑Tune low‑risk auto‑apply: Off
- GEO: adaptive (Redis if available)
- TLS: manual choice in Setup Wizard (LE HTTP‑01 / LE DNS‑01 / Custom cert / Self‑signed). Random subdomain available only with DNS‑01 + DNS‑API
- Tor native mode: Off (toggle in UI)
- MAC isolation/randomization: Off by default; with sanity guard and self‑test (planned)
- Multi‑uplink/SNAT: Off by default; framework ready (planned)

## Next steps (follow-up PRs)

- Template rendering for HAProxy/3proxy; expose/hide implementation
- Self‑test (publish/TLS/DNS‑API/firewall) with actionable report
- Setup Wizard (TLS/DNS manual choice, Random subdomain via DNS‑API)
- MAC features: enable/disable/randomize/reapply/revert, scheduler (manual), Check Support, MAC events
- Multi‑uplink: fwmark + policy routing + SNAT; health checks, failover, stickiness
- TLS fallback policy: graceful HTTPS disable on LE errors, retries, alerts
- Export: endpoints with filters and one‑click presets (wired up)
- Resource Governor (cgroups v2) tuning and watchdogs/guardrails

## Testing

- Install: sudo bash scripts/connexa-free-proxy.sh
- Check: poolproxyctl status
- API: uvicorn api.server:app --host 0.0.0.0 --port 8080
- Self‑test (placeholder): poolproxyctl selftest run publish

## Notes

- For valid HTTPS you need your domain. Random subdomain works only within your zone via DNS‑API (e.g., Cloudflare)
- On LXC/OpenVZ some network features (MAC, policy routing) may be restricted — self‑test will warn
