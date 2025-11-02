# Connexa Free Proxy — стартовый каркас (MVP)

Согласованные дефолты
- Пул Tor-нод: 50 (масштабируемо до 500)
- Внешний протокол: SOCKS5 (по умолчанию), режим доступа: both (auth + direct via whitelist)
- Ротация: 5m (любое значение/cron)
- Safety mode: Balanced
- Auto Snapshot+Rollback: On
- Shadow-Canary default: Off (в Perf first — On)
- Auto-Tune low-risk auto-apply: Off
- GEO: adaptive (Redis, если доступен)
- TLS: ручной выбор в Setup Wizard (LE HTTP‑01, LE DNS‑01 через провайдера, Custom cert, Self‑signed). Random subdomain доступен при DNS‑01 + DNS‑API.
- Tor native mode: Off (кнопка для быстрого выключения внешней публикации)
- MAC isolation/randomization: Off (кнопки, sanity guard, self-test)
- Multi-uplink/SNAT: Off (готово к включению)

Быстрый старт
1) Настройки: /etc/connexa/config.yaml (или Setup Wizard после установки)
2) Установка:
   sudo bash scripts/connexa-free-proxy.sh
3) Проверка:
   - CLI: poolproxyctl status
   - API: uvicorn api.server:app --host 0.0.0.0 --port 8080 (из /opt/connexa)
   - Self-test: poolproxyctl selftest run publish
4) Публикация прокси:
   - По умолчанию SOCKS5: SERVER_IP:40000..(40000+POOL_SIZE-1)
   - Экспорт пресетов: верхняя панель → Export Presets
5) Ротация:
   - Таймер 5m (systemd timer)
   - Кнопки: Rotate All / Canary / Shadow-Canary / Blue-Green

Основные команды (CLI)
- poolproxyctl init/start/stop/restart/status
- expose|hide, external-protocol set, access-mode set
- rotate-interval set 5m|300s|1h|cron:...
- set-countries US,DE --random
- newnym [node|all]
- whitelist add/remove/list
- export token/preset …
- geo mode/resolve/providers …
- mac enable/disable/randomize/reapply/status/selftest
- uplink list/map/rebalance/failover
- selftest run/report
- snapshot create/restore/list
- safety set perf|balanced|coverage
- rotate canary|shadow-canary|all; bluegreen prepare|switch|rollback
- resources profile set light|balanced|aggressive
- autotune suggest|apply|history

Примечания
- Для валидного HTTPS нужен ваш домен. Random subdomain доступен в вашей зоне через DNS‑API (Cloudflare/Route53).
- В SOCKS5 режиме утечек DNS нет (remote DNS).
- На LXC/OpenVZ часть сетевых функций (MAC, policy routing) может быть недоступна — self-test предупредит.

Лицензия: MIT (по умолчанию, можно изменить).