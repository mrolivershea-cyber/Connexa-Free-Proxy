from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pathlib import Path
import yaml
import socket
from typing import Dict

CONFIG_PATH = Path("/etc/connexa/config.yaml")
TOR_DATA_DIR = Path("/var/lib/tor/pool")

router = APIRouter(prefix="/ops", tags=["ops"])

def load_cfg() -> dict:
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f) or {}

def read_cookie_hex(node_i: int) -> str:
    cookie = TOR_DATA_DIR / f"node-{node_i}" / "control_auth_cookie"
    return cookie.read_bytes().hex()

def send_newnym(ctrl_port: int, cookie_hex: str, host: str = "127.0.0.1", timeout=2.0) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, ctrl_port))
        try:
            s.recv(1024)  # banner (optional)
        except Exception:
            pass
        s.sendall(f"AUTHENTICATE {cookie_hex}\r\n".encode())
        resp = s.recv(1024).decode(errors="ignore")
        if not resp.startswith("250"):
            return f"AUTH FAIL: {resp.strip()}"
        s.sendall(b"SIGNAL NEWNYM\r\n")
        resp = s.recv(1024).decode(errors="ignore")
        if not resp.startswith("250"):
            return f"NEWNYM FAIL: {resp.strip()}"
        return "OK"
    except Exception as e:
        return f"ERR: {e}"
    finally:
        try:
            s.close()
        except Exception:
            pass

@router.post("/rotation/newnym")
def rotation_newnym():
    c = load_cfg()
    pool_size = int(c.get("pool_size", 50))
    results: Dict[int, str] = {}
    for i in range(1, pool_size + 1):
        ctrl = 10510 + (i - 1)
        try:
            ck = read_cookie_hex(i)
        except Exception as e:
            results[i] = f"COOKIE ERR: {e}"
            continue
        results[i] = send_newnym(ctrl, ck)
    return JSONResponse({"result": results, "count": len(results)})
