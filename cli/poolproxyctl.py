#!/usr/bin/env python3
import sys, os, json, click, yaml, subprocess, re, random, socket
from pathlib import Path
from typing import List, Optional

CONFIG_PATH = Path("/etc/connexa/config.yaml")
HAPROXY_TMPL = Path("/etc/haproxy/haproxy.cfg.tmpl")
HAPROXY_CFG  = Path("/etc/haproxy/haproxy.cfg")
THREEPROXY_TMPL = Path("/etc/3proxy/3proxy.cfg.tmpl")
THREEPROXY_CFG  = Path("/etc/3proxy/3proxy.cfg")
WHITELIST_ACL = Path("/etc/connexa/whitelist.acl")
TOR_POOL_DIR = Path("/etc/tor/pool")
TOR_DATA_DIR = Path("/var/lib/tor/pool")

# ---------- helpers ----------
def sh(cmd: List[str], check=True) -> subprocess.CompletedProcess:
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
    # Programmatically generate HAProxy config mapping external ports to local 3proxy ports (NOAUTH 42000+)
    lines = [
        "global",
        "    daemon",
        "    maxconn 20480",
        "",
        "defaults",
        "    mode tcp",
        "    timeout connect 5s",
        "    timeout client  1m",
        "    timeout server  1m",
        "",
    ]
    for i in range(pool_size):
        ext = port_start + i
        beport = 42000 + i
        lines += [
            f"frontend fe_{ext}",
            f"    bind *:{ext}",
            f"    default_backend be_{beport}",
            "",
            f"backend be_{beport}",
            f"    server s1 127.0.0.1:{beport} check",
            "",
        ]
    HAPROXY_CFG.write_text("\n".join(lines) + "\n")


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
            f'parent 1000 socks5 127.0.0.1 {parent_port} "" ""',
        ]
        # NOAUTH backend
        noauth_p = 42000 + (i - 1)
        cfg_lines += [
            f"# node {i} NOAUTH",
            "auth none",
            "allow *",
            f"socks -n -a -p{noauth_p} -i127.0.0.1 -e127.0.0.1",
            f'parent 1000 socks5 127.0.0.1 {parent_port} "" ""',
        ]
    THREEPROXY_CFG.write_text("\n".join(cfg_lines) + "\n")


def write_whitelist(ips: List[str]):
    lines = []
    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue
        lines.append(ip)
    if "127.0.0.1" not in lines:
        lines.append("127.0.0.1")
    WHITELIST_ACL.write_text("\n".join(lines) + "\n")

# ---------- helpers: export ----------
def build_export_endpoints(c: dict, host_override: Optional[str] = None) -> List[str]:
    external = c.get("external", {}) or {}
    pool_size = int(c.get("pool_size", 50))
    port_start = int(external.get("port_start", 40000))
    protocol = (external.get("protocol_default") or "socks5").lower()
    host = host_override or external.get("host") or "127.0.0.1"
    ports = range(port_start, port_start + pool_size)
    scheme = "socks5" if "socks" in protocol else "http"
    return [f"{scheme}://{host}:{p}" for p in ports]

# ---------- helpers: mac ----------
def list_ifaces() -> List[str]:
    try:
        return [d.name for d in Path("/sys/class/net").iterdir() if d.is_dir() and d.name != "lo"]
    except Exception:
        return []

def read_mac(iface: str) -> str:
    p = Path(f"/sys/class/net/{iface}/address")
    return p.read_text().strip() if p.exists() else "00:00:00:00:00:00"

def random_mac(prefix: Optional[str] = None) -> str:
    if prefix:
        base = prefix.split(":")
        base = [b for b in base if b]
        while len(base) < 3:
            base.append("00")
        seed = base[:3]
        rnd = [random.randint(0x00, 0xFF) for _ in range(3)]
        return ":".join(seed + [f"{b:02x}" for b in rnd])
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))

def set_mac_addr(iface: str, mac: str) -> bool:
    try:
        sh(["ip", "link", "set", "dev", iface, "down"], check=False)
        r = sh(["ip", "link", "set", "dev", iface, "address", mac], check=False)
        sh(["ip", "link", "set", "dev", iface, "up"], check=False)
        return r.returncode == 0
    except Exception:
        return False

# ---------- Tor NEWNYM helpers ----------
def read_cookie_hex(node_i: int) -> str:
    cookie = TOR_DATA_DIR / f"node-{node_i}" / "control_auth_cookie"
    return cookie.read_bytes().hex()

def send_newnym(ctrl_port: int, cookie_hex: str, host: str="127.0.0.1", timeout=2.0) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, ctrl_port))
        try:
            s.recv(1024)
        except Exception:
            pass
        s.sendall(f"AUTHENTICATE {cookie_hex}\r\n".encode())
        r = s.recv(1024).decode(errors="ignore")
        if not r.startswith("250"):
            return f"AUTH FAIL: {r.strip()}"
        s.sendall(b"SIGNAL NEWNYM\r\n")
        r = s.recv(1024).decode(errors="ignore")
        if not r.startswith("250"):
            return f"NEWNYM FAIL: {r.strip()}"
        return "OK"
    except Exception as e:
        return f"ERR: {e}"
    finally:
        try:
            s.close()
        except Exception:
            pass

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
        sh(["which", "haproxy"]); sh(["which", "3proxy"]); sh(["which", "tor"])
    except Exception as e:
        ok = False; msgs.append(f"binaries: {e}")
    for svc in ["haproxy", "3proxy"]:
        r = sh(["systemctl", "is-enabled", svc], check=False)
        msgs.append(f"{svc}: enabled={{r.returncode==0}}")
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
    sh(["systemctl", "restart", "haproxy"]); sh(["systemctl", "restart", "3proxy"], check=False)
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

# -------- export via CLI ----------
@cli.group("export")
def export_grp():
    """Экспорт списка эндпоинтов"""
    pass

@export_grp.command("txt")
@click.option("--host", help="Override host for endpoints (default from config.external.host)")
def export_txt(host: Optional[str]):
    c = load_cfg()
    eps = build_export_endpoints(c, host_override=host)
    print("\n".join(eps))

@export_grp.command("csv")
@click.option("--host", help="Override host for endpoints (default from config.external.host)")
def export_csv(host: Optional[str]):
    c = load_cfg()
    eps = build_export_endpoints(c, host_override=host)
    print("endpoint")
    print("\n".join(eps))

@export_grp.command("json")
@click.option("--host", help="Override host for endpoints (default from config.external.host)")
def export_json(host: Optional[str]):
    c = load_cfg()
    eps = build_export_endpoints(c, host_override=host)
    print(json.dumps({"endpoints": eps, "count": len(eps)}, indent=2))

# -------- MAC isolation ----------
@cli.group()
def mac():
    """Управление MAC-адресами (randomize/set/status/reapply/selftest)."""
    pass

@mac.command("status")
def mac_status():
    ifaces = list_ifaces()
    data = {iface: read_mac(iface) for iface in ifaces}
    print(json.dumps(data, indent=2))

@mac.command("randomize")
@click.option("--iface", "iface", help="Интерфейс (по умолчанию все)")
@click.option("--prefix", "prefix", help="Префикс, например 02:11:22")
def mac_randomize(iface: Optional[str], prefix: Optional[str]):
    targets = [iface] if iface else list_ifaces()
    for ifn in targets:
        newm = random_mac(prefix)
        ok = set_mac_addr(ifn, newm)
        print(f"[mac] {ifn}: set {newm} -> {'OK' if ok else 'FAIL'}")

@mac.command("set")
@click.argument("iface")
@click.argument("macaddr")
def mac_set(iface: str, macaddr: str):
    ok = set_mac_addr(iface, macaddr)
    print(f"[mac] {iface}: set {macaddr} -> {'OK' if ok else 'FAIL'}")

@mac.command("reapply")
def mac_reapply():
    c = load_cfg()
    mapping = (c.get("network", {}) or {}).get("mac_persist", {}) or {}
    if not mapping:
        print("[mac] nothing to reapply (network.mac_persist empty)")
        return
    for ifn, macaddr in mapping.items():
        ok = set_mac_addr(ifn, macaddr)
        print(f"[mac] {ifn}: reapply {macaddr} -> {'OK' if ok else 'FAIL'}")

@mac.command("selftest")
def mac_selftest():
    r = sh(["which", "ip"], check=False)
    print("[mac] ip tool:", "OK" if r.returncode == 0 else "MISSING")
    print("[mac] ifaces:", ", ".join(list_ifaces()))

# -------- Uplink/SNAT (skeleton) ----------
@cli.group()
def uplink():
    """Multi-uplink/SNAT (скелет команд add/del/list)."""
    pass

@uplink.command("list")
def uplink_list():
    r = sh(["ip", "route", "show"], check=False)
    print(r.stdout or r.stderr)

@uplink.command("add")
@click.argument("name")
@click.option("--dev", required=True, help="Интерфейс, например eth1")
@click.option("--gw", required=True, help="Шлюз, например 192.0.2.1")
@click.option("--metric", default=100, type=int)
def uplink_add(name: str, dev: str, gw: str, metric: int):
    print(f"[uplink] add name={{name}} dev={{dev}} gw={{gw}} metric={{metric}} (placeholder)")

@uplink.command("del")
@click.argument("name")
def uplink_del(name: str):
    print(f"[uplink] del name={{name}} (placeholder)")

# -------- Tor rotation via CLI ----------
@cli.group()
def rotate():
    """Ротация Tor: NEWNYM или перезапуск"""
    pass

@rotate.command("newnym")
@click.option("--nodes", help="Список узлов, например 1,2,5 (по умолчанию все)")
def rotate_newnym(nodes: Optional[str]):
    c = load_cfg()
    pool = int(c.get("pool_size", 50))
    if nodes:
        ids = []
        for part in nodes.split(","):
            part = part.strip()
            if part:
                try:
                    ids.append(int(part))
                except Exception:
                    pass
    else:
        ids = list(range(1, pool+1))
    ok = 0
    for i in ids:
        ctrl = 10510 + (i-1)
        try:
            ck = read_cookie_hex(i)
        except Exception as e:
            print(f"[rotate] node {i}: COOKIE ERR {e}")
            continue
        res = send_newnym(ctrl, ck)
        print(f"[rotate] node {i}: {{res}}")
        if res == "OK":
            ok += 1
    print(f"[rotate] OK={{ok}}/{{len(ids)}}")

@rotate.command("restart")
def rotate_restart():
    c = load_cfg()
    pool = int(c.get("pool_size", 50))
    for i in range(1, pool+1):
        unit = f"tor-pool@{i}.service"
        print(f"[rotation] restarting {{unit}}...")
        sh(["systemctl", "restart", unit], check=False)
    print("[rotation] done.")

if __name__ == "__main__":
    cli()