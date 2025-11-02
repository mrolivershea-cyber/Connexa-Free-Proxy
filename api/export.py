from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse
from typing import Optional, List
import yaml
from pathlib import Path

CONFIG_PATH = Path("/etc/connexa/config.yaml")
router = APIRouter(prefix="/export", tags=["export"])

def load_cfg():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

def build_endpoints(c: dict, host_override: Optional[str] = None) -> List[str]:
    external = c.get("external", {}) or {}
    pool_size = int(c.get("pool_size", 50))
    port_start = int(external.get("port_start", 40000))
    protocol = (external.get("protocol_default") or "socks5").lower()
    host = host_override or external.get("host") or "127.0.0.1"

    ports = range(port_start, port_start + pool_size)
    scheme = "socks5" if "socks" in protocol else "http"
    return [f"{scheme}://{host}:{p}" for p in ports]

@router.get("/txt")
def export_txt(host: Optional[str] = None):
    c = load_cfg()
    lines = build_endpoints(c, host_override=host)
    return Response("\n".join(lines) + "\n", media_type="text/plain")

@router.get("/csv")
def export_csv(host: Optional[str] = None):
    c = load_cfg()
    lines = build_endpoints(c, host_override=host)
    csv = "endpoint\n" + "\n".join(lines) + "\n"
    return Response(csv, media_type="text/csv")

@router.get("/json")
def export_json(host: Optional[str] = None):
    c = load_cfg()
    lines = build_endpoints(c, host_override=host)
    return JSONResponse({"endpoints": lines, "count": len(lines)})
