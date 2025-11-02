from fastapi import APIRouter, Request, HTTPException, status, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import Optional
from pathlib import Path
import subprocess

router = APIRouter(tags=["admin"])

# Do not auto-raise 401; we will decide when to challenge
security = HTTPBasic(auto_error=False)

ADMIN_FILE = Path("/etc/connexa/haproxy-admin")
HAPROXY_CFG = Path("/etc/haproxy/haproxy.cfg")
STATS_PORT = 8081
REALM = 'Basic realm="Connexa Free Proxy"'

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

def html_page(body: str, status_code: int = 200, headers: Optional[dict] = None) -> HTMLResponse:
    return HTMLResponse(f"""
<!doctype html>
<html lang=\"ru\">
<head>
<meta charset=\"utf-8\">
<title>Connexa Free Proxy</title>
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
""", status_code=status_code, headers=headers or {})

def unauthorized():
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized",
        headers={"WWW-Authenticate": REALM},
    )

def validate_password(pwd: str) -> Optional[str]:
    if len(pwd) < 6: return "Пароль должен быть не короче 6 символов."
    if " " in pwd: return "Пароль не должен содержать пробелы."
    if ":" in pwd: return "Пароль не должен содержать двоеточие (:)."
    return None

def enable_stats_external(user: str, pwd: str):
    # Update stats auth and expose on 0.0.0.0 after password is set
    if HAPROXY_CFG.exists():
        content = HAPROXY_CFG.read_text()
        out = []
        for line in content.splitlines():
            s = line.strip()
            if s.startswith("stats auth "):
                line = f"    stats auth {user}:{pwd}"
            if s.startswith("bind ") and f":{STATS_PORT}" in s:
                line = f"    bind 0.0.0.0:{STATS_PORT}"
            out.append(line)
        HAPROXY_CFG.write_text("\n".join(out) + "\n")
    subprocess.run(["bash","-lc","command -v ufw >/dev/null 2>&1 && ufw allow 8081/tcp || true"], check=False)
    subprocess.run(["systemctl","restart","haproxy"], check=False)

@router.get("/admin")
def admin_home(creds: Optional[HTTPBasicCredentials] = Depends(security)):
    u, p = read_creds()
    # First run: no Basic, ask to set password
    if u == "admin" and p == "admin":
        return RedirectResponse("/admin/first-run", status_code=302)
    # After password set: require Basic
    if creds is None or creds.username != u or creds.password != p:
        unauthorized()
    return html_page(f"""
<h1>Connexa Free Proxy — админка</h1>
<p>Вы вошли как <b>{u}</b>.</p>
<p><a href=\"/admin/change\">Сменить пароль</a></p>
<p class=\"note\">Страница статистики HAProxy доступна на порту 8081.</p>
""")

@router.get("/admin/first-run")
def first_run_get():
    u, p = read_creds()
    if not (u == "admin" and p == "admin"):
        return RedirectResponse("/admin", status_code=302)
    return html_page("""
<h1>Создать пароль администратора</h1>
<form method=\"POST\" action=\"/admin/first-run\">
  <label>Новый пароль
    <input type=\"password\" name=\"new_password\" minlength=\"6\" required>
  </label>
  <button type=\"submit\">Установить</button>
</form>
<p class=\"note\">Требования: минимум 6 символов, без пробелов и двоеточия (:).</p>
""")

@router.post("/admin/first-run")
async def first_run_post(request: Request):
    u, p = read_creds()
    if not (u == "admin" and p == "admin"):
        return RedirectResponse("/admin", status_code=302)
    form = await request.form()
    new_password = (form.get("new_password") or "").strip()
    err = validate_password(new_password)
    if err:
        return html_page(f'<h1 class="error">Ошибка</h1><p>{err}</p><p><a href="/admin/first-run">Назад</a></p>')
    write_creds("admin", new_password)
    enable_stats_external("admin", new_password)
    return html_page('<h1 class="success">Готово</h1><p>Пароль установлен. Зайдите в <a href="/admin">админку</a> — браузер попросит логин/пароль (realm: Connexa Free Proxy).</p>')

@router.get("/admin/change")
def admin_change_get(creds: Optional[HTTPBasicCredentials] = Depends(security)):
    u, p = read_creds()
    if u == "admin" and p == "admin":
        return RedirectResponse("/admin/first-run", status_code=302)
    if creds is None or creds.username != u or creds.password != p:
        unauthorized()
    return html_page("""
<h1>Сменить пароль</h1>
<form method=\"POST\" action=\"/admin/change\">
  <label>Новый пароль
    <input type=\"password\" name=\"new_password\" minlength=\"6\" required>
  </label>
  <button type=\"submit\">Сменить</button>
</form>
<p class=\"note\">Требования: минимум 6 символов, без пробелов и двоеточия (:).</p>
""")

@router.post("/admin/change")
async def admin_change_post(request: Request, creds: Optional[HTTPBasicCredentials] = Depends(security)):
    u, p = read_creds()
    if u == "admin" and p == "admin":
        return RedirectResponse("/admin/first-run", status_code=302)
    if creds is None or creds.username != u or creds.password != p:
        unauthorized()
    form = await request.form()
    new_password = (form.get("new_password") or "").strip()
    err = validate_password(new_password)
    if err:
        return html_page(f'<h1 class=\"error\">Ошибка</h1><p>{err}</p><p><a href=\"/admin/change\">Назад</a></p>')
    write_creds("admin", new_password)
    enable_stats_external("admin", new_password)
    return html_page('<h1 class="success">Готово</h1><p>Пароль обновлён. HAProxy stats доступен на порту 8081. <a href="/admin">Назад</a></p>')