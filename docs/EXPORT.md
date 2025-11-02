# Export endpoints and CLI

API:
- GET /export/txt — текстовый список прокси
- GET /export/csv — CSV с колонкой `endpoint`
- GET /export/json — JSON с массивом `endpoints`

Параметры:
- query `host` — переопределить хост, если не указан в `config.external.host`

Примеры:
```bash
curl -s "http://127.0.0.1:8080/export/txt?host=proxy.example.com"
curl -s "http://127.0.0.1:8080/export/csv"
curl -s "http://127.0.0.1:8080/export/json" | jq
```

CLI:
```bash
poolproxyctl export txt --host proxy.example.com
poolproxyctl export csv
poolproxyctl export json
```

Логика экспорта:
- Берётся `pool_size`, `external.port_start`, `external.protocol_default`, `external.host` из `/etc/connexa/config.yaml`.
- Диапазон портов: `[port_start .. port_start + pool_size - 1]`
- Схема: `socks5://` для SOCKS, иначе `http://`