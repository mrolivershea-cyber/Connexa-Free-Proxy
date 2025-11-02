#!/usr/bin/env python3
import sys, os, json, click, yaml, subprocess, re
from pathlib import Path

CONFIG_PATH = Path("/etc/connexa/config.yaml")
HAPROXY_TMPL = Path("/etc/haproxy/haproxy.cfg.tmpl")
HAPROXY_CFG  = Path("/etc/haproxy/haproxy.cfg")
THREEPROXY_TMPL = Path("/etc/3proxy/3proxy.cfg.tmpl")
THREEPROXY_CFG  = Path("/etc/3proxy/3proxy.cfg")
WHITELIST_ACL = Path("/etc/connexa/whitelist.acl")
TOR_POOL_DIR = Path("/etc/tor/pool")
TOR_DATA_DIR = Path("/var/lib/tor/pool")

# ---------- helpers ----------
def sh(cmd: list[str], check=True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, text=True, capture_output=True)

def load_cfg():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

def save_cfg(c):
    with open(CONFIG_PATH, "w") as f:
        yaml.safe_dump(c, f, sort_keys=False, allow_unicode=True)

def ensure_dirs():
    for p in [TOR_POOL_DIR, TOR_DATA_DIR, WHITELIST_ACL.parent, HAPROXY_CFG.parent, THREEPROXY_CFG.parent]:
        p.mkdir(parents=True, exist_ok=True)

# ---------- TOR pool init ----------
def gen_torrc(pool_size: int):
    ensure_dirs()
    for i in range(1, pool_size + 1):
        socks = 9050 + (i - 1)
        ctrl  = 10510 + (i - 1)
        dd = TOR_DATA_DIR / f"node-{i}"
        dd.mkdir(parents=True, exist_ok=True)
        torrc = TOR_POOL_DIR / f"torrc-{i}"
        content = f"""
DataDirectory {dd}
SocksPort 127.0.0.1:{socks}
ControlPort 127.0.0.1:{ctrl}
CookieAuthentication 1
AvoidDiskWrites 1
Log notice file /var/log/tor/pool/tor-{i}.log
""".strip() + "\n"
        torrc.write_text(content)
    # permissions for debian-tor
    try:
        sh(["chown", "-R", "debian-tor:debian-tor", str(TOR_DATA_DIR)])
    except Exception:
        pass

def start_tor_pool(pool_size: int):
    for i in range(1, pool_size + 1):
        unit = f"tor-pool@{i}.service"
        sh(["systemctl", "enable", "--now", unit])

# ---------- Rendering ----------
def render_haproxy(port_start: int, pool_size: int):
    if not HAPROXY_TMPL.exists():
        raise FileNotFoundError(f"Missing template {HAPROXY_TMPL}")
    port_end = port_start + pool_size - 1
    tmpl = HAPROXY_TMPL.read_text()
    cfg = tmpl.replace("{{PORT_RANGE_START}}", str(port_start)).replace("{{PORT_RANGE_END}}", str(port_end))
    HAPROXY_CFG.write_text(cfg)

def render_3proxy(pool_size: int):
    cfg_lines = [
        "daemon",
        "nscache 65536",
    ]
    for i in range(1, pool_size + 1):
        parent_port = 9050 + (i - 1)
        # AUTH backend (placeholder auth none for MVP)
        auth_p = 41000 + (i - 1)
        cfg_lines += [
            f"# node {i} AUTH placeholder",
            "auth none",
            "allow *",
            f"socks -n -a -p{auth_p} -i127.0.0.1 -e127.0.0.1",
            f"parent 1000 socks5 127.0.0.1 {parent_port} \"\" \"\"",
        ]
        # NOAUTH backend
        noauth_p = 42000 + (i - 1)
        cfg_lines += [
            f"# node {i} NOAUTH",
            "auth none",
            "allow *",
            f"socks -n -a -p{noauth_p} -i127.0.0.1 -e127.0.0.1",
            f"parent 1000 socks5 127.0.0.1 {parent_port} \"\" \"\"",
        ]
    THREEPROXY_CFG.write_text("\n".join(cfg_lines) + "\n")

def write_whitelist(ips: list[str]):
    lines = []
    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue
        lines.append(ip)
    if "127.0.0.1" not in lines:
        lines.append("127.0.0.1")
    WHITELIST_ACL.write_text("\n".join(lines) + "\n")

# ---------- CLI ----------
@click.group()
def cli():
    """Connexa Free Proxy CLI"""
    pass

@cli.command()
def status():
    cfg = load_cfg()
    info = {
        "pool_size": cfg.get("pool_size"),
        "protocol": cfg.get("external", {}).get("protocol_default"),
        "access_mode": cfg.get("external", {}).get("access_mode_default"),
        "rotation_interval": cfg.get("rotation", {}).get("interval"),
        "expose": cfg.get("external", {}).get("expose"),
    }
    print(json.dumps(info, indent=2, ensure_ascii=False))

@cli.command()
@click.option("--size", "size", type=int, required=False, help="Override pool size for init")
def init(size: int | None):
    """Подготовить и запустить пул Tor (torrc-N, systemd enable --now)."""
    cfg = load_cfg()
    pool_size = size or int(cfg.get("pool_size", 50))
    print(f"[init] Generating torrc for {pool_size} nodes...")
    gen_torrc(pool_size)
    print("[init] Starting tor pool services...")
    start_tor_pool(pool_size)
    print("[init] Done.")

@cli.command("rotate-interval")
@click.argument("interval")
def rotate_interval_cmd(interval):
    cfg = load_cfg()
    cfg.setdefault("rotation", {})["interval"] = interval
    save_cfg(cfg)
    print(f"Rotation interval set to {interval}. Перезапустите таймер systemd.")

@cli.group()
def selftest():
    """Самопроверки (publish/tls/export)."""
    pass

@selftest.command("run")
@click.argument("profile", required=False, default="publish")
def selftest_run(profile):
    ok = True
    msgs = []
    try:
        sh(["which", "haproxy"]) ; sh(["which", "3proxy"]) ; sh(["which", "tor"]) 
    except Exception as e:
        ok = False; msgs.append(f"binaries: {e}")
    # check services
    for svc in ["haproxy", "3proxy"]:
        r = sh(["systemctl", "is-enabled", svc], check=False)
        msgs.append(f"{svc}: enabled={{r.returncode==0}}")
    # check one tor unit
    r = sh(["systemctl", "is-active", "tor-pool@1"], check=False)
    msgs.append(f"tor-pool@1 active={{r.returncode==0}}")
    print("\n".join(["[selftest] "+m for m in msgs]))
    print("[selftest] RESULT=", "OK" if ok else "FAIL")

@cli.command()
def expose():
    cfg = load_cfg()
    pool_size = int(cfg.get("pool_size", 50))
    port_start = int(cfg.get("external", {}).get("port_start", 40000))
    wl = cfg.get("security", {}).get("whitelist_direct", [])
    print("[expose] Rendering HAProxy...")
    render_haproxy(port_start, pool_size)
    print("[expose] Rendering 3proxy...")
    render_3proxy(pool_size)
    print("[expose] Writing whitelist...")
    write_whitelist(wl)
    print("[expose] Restart services...")
    sh(["systemctl", "restart", "haproxy"]) ; sh(["systemctl", "restart", "3proxy"], check=False)
    # firewall (best-effort)
    try:
        port_end = port_start + pool_size - 1
        sh(["ufw", "allow", f"{port_start}:{port_end}/tcp"], check=False)
    except Exception:
        pass
    print("[expose] Done.")

@cli.command()
def hide():
    print("[hide] Stopping HAProxy (external ports)")
    sh(["systemctl", "stop", "haproxy"], check=False)
    print("[hide] Done.")

if __name__ == "__main__":
    cli()