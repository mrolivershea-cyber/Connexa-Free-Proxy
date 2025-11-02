from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn
import yaml
from pathlib import Path

CONFIG_PATH = Path("/etc/connexa/config.yaml")
app = FastAPI(title="Connexa Free Proxy API", version="0.1.0")

def cfg():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

@app.get("/healthz")
def healthz():
    return {"status":"ok"}

@app.get("/status")
def status():
    c = cfg()
    return JSONResponse({
        "pool_size": c.get("pool_size"),
        "protocol": c.get("external",{}).get("protocol_default"),
        "access_mode": c.get("external",{}).get("access_mode_default"),
        "rotation_interval": c.get("rotation",{}).get("interval"),
    })

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
