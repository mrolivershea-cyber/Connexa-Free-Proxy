#!/usr/bin/env python3
import sys, os, json, click, yaml
from pathlib import Path

CONFIG_PATH = Path("/etc/connexa/config.yaml")

def load_cfg():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

def save_cfg(c):
    with open(CONFIG_PATH, "w") as f:
        yaml.safe_dump(c, f, sort_keys=False, allow_unicode=True)

@click.group()
def cli():
    """Connexa Free Proxy CLI (MVP)"""
    pass

@cli.command()
def status():
    """Показать краткий статус пула и настроек."""
    cfg = load_cfg()
    print(json.dumps({
        "pool_size": cfg.get("pool_size"),
        "protocol": cfg.get("external", {}).get("protocol_default"),
        "access_mode": cfg.get("external", {}).get("access_mode_default"),
        "rotation_interval": cfg.get("rotation", {}).get("interval"),
        "safety_mode": cfg.get("safety_mode"),
        "expose": cfg.get("external", {}).get("expose"),
    }, indent=2, ensure_ascii=False))

@cli.command("rotate-interval")
@click.argument("interval")
def rotate_interval_cmd(interval):
    """Установить интервал ротации (напр. 5m, 300s, 1h, cron:*/5 * * * *)."""
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
    print(f"[selftest] Running profile={profile} ...")
    # TODO: Реализовать проверки портов, биндов, DNS-API, firewall
    print("[selftest] OK (placeholder)")

@cli.command()
def expose():
    """Опубликовать внешние порты (рендер HAProxy/3proxy, открыть firewall)."""
    print("[expose] Rendering templates and reloading services (placeholder)")

@cli.command()
def hide():
    """Скрыть внешние порты."""
    print("[hide] Closing ports and reloading services (placeholder)")

if __name__ == "__main__":
    cli()
