from fastapi import APIRouter, Depends, Request, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pathlib import Path
import subprocess
import yaml

router = APIRouter(tags=["admin"])
security = HTTPBasic()

ADMIN_FILE = Path("/etc/connexa/haproxy-admin")
HAPROXY_CFG = Path("/etc/haproxy/haproxy.cfg")
STATS_PORT = 8081

def read_creds() -> tuple[str, str]:
    if ADMIN_FILE.exists():
        try:
            user, pwd = ADMIN_FILE.read_text().strip().split(":", 1)
            return user, pwd
        except Exception:
            pass
    return "admin", "admin"

def write_creds(user: str, pwd: str):
    ADMIN_FILE.parent.mkdir(parents=True, exist_ok=True)
    ADMIN_FILE.write_text(f"{user}:{pwd}")
    ADMIN_FILE.chmod(0o600)

def require_auth(creds: HTTPBasicCredentials = Depends(security)) -> tuple[str, str]:
    u, p = read_creds()
    if creds.username != u or creds.password != p:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    return u, p

def enable_stats_external(user: str, pwd: str):
    if HAPROXY_CFG.exists():
        content = HAPROXY_CFG.read_text()
        lines = []
        for line in content.splitlines():
            if line.strip().startswith("stats auth "):
                line = f"    stats auth {user}:{pwd}"
            if line.strip().startswith("bind ") and f":{STATS_PORT}" in line:
                line = f"    bind 0.0.0.0:{STATS_PORT}"
            lines.append(line)
        HAPROXY_CFG.write_text("\n".join(lines) + "\n")
    subprocess.run(["bash", "-lc", "command -v ufw >/dev/null 2>&1 && ufw allow 8081/tcp || true"], check=False)
    subprocess.run(["systemctl", "restart", "haproxy"], check=False)

def html_page(body: str) -> HTMLResponse:
    return HTMLResponse(f"""
<!doctype html>
<html lang=\"ru\">
<head>
<meta charset=\"utf-8\">
<title>Connexa Admin</title>
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<style>
body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; }}
.card {{ max-width: 520px; border: 1px solid #ddd; border-radius: 8px; padding: 1.25rem; }}
h1 {{ font-size: 1.25rem; margin: 0 0 1rem; }}
label {{ display: block; margin-top: 0.75rem; }}
input[type=password] {{ width: 100%; padding: 0.5rem; }}
button {{ margin-top: 1rem; padding: 0.5rem 0.75rem; }}
.note {{ margin-top:0.5rem; color:#666; font-size: 0.9rem; }}
.success {{ color: #0a0; }}
.error {{ color: #a00; }}
</style>
</head>
<body>
<div class=\"card\">
{body}
</div>
</body>
</html>
""")

@router.get("/admin")
def admin_home(userpwd=Depends(require_auth)):
    u, p = userpwd
    if u == "admin" and p == "admin":
        return RedirectResponse(url="/admin/change", status_code=302)
    return html_page(f"""
<h1>Админка Connexa</h1>
<p>Вы вошли как <b>{u}</b>.</p>
<p><a href=\"/admin/change\">Сменить пароль</a></p>
<p class=\"note\">Страница статистики HAProxy доступна на порту 8081 после смены пароля.</p>
""")

@router.get("/admin/change")
def admin_change_get(userpwd=Depends(require_auth)):
    u, p = userpwd
    return html_page(f"""
<h1>Сменить пароль</h1>
<form method=\"POST\" action=\"/admin/change\">
  <label>Новый пароль
    <input type=\"password\" name=\"new_password\" minlength=\"6\" required>
  </label>
  <button type=\"submit\">Сменить</button>
</form>
<p class=\"note\">После смены пароль вступит в силу для админки и HAProxy stats (порт 8081).</p>
""")

@router.post("/admin/change")
async def admin_change_post(request: Request, userpwd=Depends(require_auth)):
    u, p = userpwd
    form = await request.form()
    new_password = (form.get("new_password") or "").strip()
    if len(new_password) < 6:
        return html_page('<h1 class="error">Ошибка</h1><p>Пароль должен быть не короче 6 символов.</p><p><a href="/admin/change">Назад</a></p>')
    write_creds("admin", new_password)
    enable_stats_external("admin", new_password)
    return html_page('<h1 class="success">Готово</h1><p>Пароль обновлён. HAProxy stats доступен извне на порту 8081.</p><p><a href="/admin">В админку</a></p>')
