from fastapi import APIRouter
import yaml
from pathlib import Path

CONFIG_PATH = Path("/etc/connexa/config.yaml")
router = APIRouter(prefix="/setup", tags=["setup"])

def load_cfg():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

def save_cfg(c):
    with open(CONFIG_PATH, "w") as f:
        yaml.safe_dump(c, f, sort_keys=False, allow_unicode=True)

@router.get("/tls")
def get_tls():
    c = load_cfg()
    return c.get("tls", {})

@router.post("/tls")
def set_tls(payload: dict):
    c = load_cfg()
    c["tls"] = {
        "mode": payload.get("mode", "disabled"),
        "domains": payload.get("domains", []),
        "random_subdomain": payload.get("random_subdomain", False),
        "dns_provider": payload.get("dns_provider", "cloudflare"),
        "dns_api_token": payload.get("dns_api_token", ""),
        "auto_renew": bool(payload.get("auto_renew", True)),
        "fallback_policy_enabled": bool(payload.get("fallback_policy_enabled", True)),
    }
    save_cfg(c)
    return {"status": "ok", "tls": c["tls"]}