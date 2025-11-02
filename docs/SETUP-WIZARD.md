# Setup Wizard (API MVP)

- TLS manual choice via API endpoints:
  - GET /setup/tls — current TLS config
  - POST /setup/tls — set TLS config

Example (curl):

```bash
curl -s http://127.0.0.1:8080/setup/tls | jq

curl -s -X POST http://127.0.0.1:8080/setup/tls \
  -H 'Content-Type: application/json' \
  -d '{
    "mode": "le-http01", 
    "domains": ["proxy.example.com"],
    "random_subdomain": false,
    "dns_provider": "cloudflare",
    "auto_renew": true,
    "fallback_policy_enabled": true
  }' | jq
``` 

- Expose/hide and Tor pool init via CLI:
  - poolproxyctl init
  - poolproxyctl expose
  - poolproxyctl hide
